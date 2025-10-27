use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::Parser;
use std::fs;
use std::path::PathBuf;

mod formatter;
mod parser;
mod scanner;
mod dirscan;
mod json_output;
mod sqlite_output;

use formatter::format_certificate_list;
use parser::parse_certificate;
use scanner::scan_certificates;

/// High-performance X.509 certificate scanner and extractor.
#[derive(Parser, Debug)]
#[command(name = "cert-dump", version = "1.2.0")]
#[command(about = "Scans files and directories for X.509 certificates (DER and PEM) with duplicate detection")]
struct Cli {
    /// File(s) or directory(ies) to scan
    #[arg(value_name = "PATH", required = true)]
    input: Vec<PathBuf>,

    /// Output directory for extracted certificates
    #[arg(short = 'o', long = "outdir", value_name = "DIR", default_value = "cert_dump")]
    outdir: PathBuf,

    /// Extract certificates to files (default: both DER and PEM)
    #[arg(long = "dump")]
    dump: bool,

    /// Extract only DER format (requires --dump)
    #[arg(long = "der")]
    der: bool,

    /// Extract only PEM format (requires --dump)
    #[arg(long = "pem")]
    pem: bool,

    /// Verbose output with additional details
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Overwrite existing directory contents
    #[arg(short = 'f', long = "force")]
    force: bool,

    /// Recursively scan directories
    #[arg(short = 'R', long = "recursive")]
    recursive: bool,

    /// Follow symbolic links during directory traversal
    #[arg(long = "follow-symlinks")]
    follow_symlinks: bool,

    /// Maximum directory recursion depth
    #[arg(long = "max-depth", value_name = "N")]
    max_depth: Option<usize>,

    /// Filter by file extensions (comma-separated, e.g., der,crt,pem)
    #[arg(long = "ext", value_name = "EXTENSIONS", value_delimiter = ',')]
    extensions: Option<Vec<String>>,

    /// Number of worker threads for parallel scanning
    #[arg(long = "threads", value_name = "N")]
    threads: Option<usize>,

    /// Maximum file size to scan in bytes (default: 512MB)
    #[arg(long = "max-file-size", value_name = "BYTES")]
    max_file_size: Option<u64>,

    /// Only emit the first occurrence of each unique certificate
    #[arg(long = "unique-only")]
    unique_only: bool,

    /// Mark duplicate certificates with annotation to first occurrence
    #[arg(long = "mark-duplicates")]
    mark_duplicates: bool,

    /// Output results as newline-delimited JSON
    #[arg(long = "json")]
    json: bool,

    /// Write results to SQLite database
    #[arg(long = "sqlite", value_name = "FILE")]
    sqlite: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Determine if we're in single-file or multi-file mode
    let is_single_file = cli.input.len() == 1 
        && cli.input[0].is_file() 
        && !cli.recursive
        && !cli.unique_only
        && !cli.mark_duplicates;

    if is_single_file {
        // Traditional single-file mode (preserves existing behavior)
        run_single_file_mode(&cli)?;
    } else {
        // Directory/multi-file mode with deduplication
        run_directory_mode(&cli)?;
    }

    Ok(())
}

/// Traditional single-file scanning mode
fn run_single_file_mode(cli: &Cli) -> Result<()> {
    let input_path = &cli.input[0];
    
    // Read the binary file
    let data = fs::read(input_path)
        .with_context(|| format!("Failed to read input file: {:?}", input_path))?;

    if cli.verbose {
        eprintln!("Scanning {} bytes from {:?}...", data.len(), input_path);
    }

    // Scan for certificates
    let found_certs = scan_certificates(&data, cli.verbose)?;

    if cli.verbose {
        eprintln!("Found {} certificate(s)", found_certs.len());
    }

    // Parse each certificate
    let mut results = Vec::new();
    for cert in found_certs {
        let parsed = parse_certificate(&cert.der).ok();
        if parsed.is_none() && cli.verbose {
            eprintln!("Warning: Failed to parse certificate at offset 0x{:X}", cert.offset);
        }
        results.push((cert, parsed));
    }

    // Extract certificates if --dump is specified
    let mut output_files = None;
    if cli.dump {
        output_files = Some(extract_certificates(&cli, &results)?);
    } else if (cli.der || cli.pem) && cli.verbose {
        eprintln!("Note: --der/--pem flags ignored without --dump");
    }

    // Print formatted output
    let formatted = format_certificate_list(&results, output_files.as_ref(), cli.verbose);
    print!("{}", formatted);

    Ok(())
}

/// Directory/multi-file scanning mode with duplicate detection
fn run_directory_mode(cli: &Cli) -> Result<()> {
    use dirscan::{ScanConfig, enumerate_files, scan_files_parallel};

    // Build scan configuration
    let config = ScanConfig {
        recursive: cli.recursive,
        follow_symlinks: cli.follow_symlinks,
        max_depth: cli.max_depth,
        extensions: cli.extensions.clone(),
        threads: cli.threads.unwrap_or_else(|| num_cpus::get().max(1)),
        max_file_size: cli.max_file_size.unwrap_or(512 * 1024 * 1024),
        unique_only: cli.unique_only,
        mark_duplicates: cli.mark_duplicates,
        verbose: cli.verbose,
    };

    // Enumerate files to scan
    let jobs = enumerate_files(cli.input.clone(), &config)?;

    if cli.verbose {
        eprintln!("Found {} file(s) to scan", jobs.len());
    }

    if jobs.is_empty() {
        eprintln!("No files found to scan");
        return Ok(());
    }

    // Initialize SQLite writer if requested
    let mut sqlite_writer = if let Some(ref db_path) = cli.sqlite {
        if cli.verbose {
            eprintln!("Initializing SQLite database: {}", db_path.display());
        }
        Some(sqlite_output::SqliteWriter::new(db_path)?)
    } else {
        None
    };

    // Begin transaction for SQLite
    if let Some(ref mut writer) = sqlite_writer {
        writer.begin_transaction()?;
    }

    // Collect results for processing
    let mut all_results = Vec::new();

    // Scan files in parallel with deduplication
    scan_files_parallel(jobs, &config, |cert_info| {
        // Parse the certificate
        let parsed = parse_certificate(&cert_info.cert.der).ok();
        if parsed.is_none() && cli.verbose {
            eprintln!(
                "Warning: Failed to parse certificate in {} at offset 0x{:X}",
                cert_info.path.display(),
                cert_info.cert.offset
            );
        }

        all_results.push((cert_info, parsed));
        Ok(())
    })?;

    // Write to SQLite if enabled
    if let Some(ref writer) = sqlite_writer {
        for (cert_info, parsed_opt) in &all_results {
            writer.write_certificate(cert_info, parsed_opt.as_ref())?;
        }
    }

    // Commit SQLite transaction
    if let Some(ref mut writer) = sqlite_writer {
        writer.commit()?;
        
        if cli.verbose {
            let (unique, total) = writer.get_stats()?;
            eprintln!(
                "SQLite: {} unique certificate(s), {} total occurrence(s) written",
                unique, total
            );
        }
    }

    // Output results based on format
    if cli.json {
        output_json(&all_results)?;
    } else {
        format_directory_results(&all_results, cli);
    }

    Ok(())
}

/// Output results as newline-delimited JSON
fn output_json(
    results: &[(dirscan::CertWithDuplicateInfo, Option<parser::ParsedCert>)],
) -> Result<()> {
    use json_output::JsonCertificate;

    for (cert_info, parsed_opt) in results {
        let json_cert = JsonCertificate::from_directory_scan(cert_info, parsed_opt.as_ref());
        println!("{}", serde_json::to_string(&json_cert)?);
    }

    Ok(())
}

/// Format and display results from directory scanning
fn format_directory_results(
    results: &[(dirscan::CertWithDuplicateInfo, Option<parser::ParsedCert>)],
    cli: &Cli,
) {
    use formatter::colors_from_env;
    let colors = colors_from_env();

    if results.is_empty() {
        println!("{}No certificates found.{}", colors.dim(), colors.reset());
        return;
    }

    println!(
        "{}{}Certificate Scan Results{}",
        colors.bold(),
        colors.bright_cyan(),
        colors.reset()
    );
    println!("{}{}{}", colors.cyan(), "=".repeat(50), colors.reset());
    println!();

    for (cert_info, parsed_opt) in results {
        format_directory_certificate(cert_info, parsed_opt.as_ref(), cli, &colors);
        println!();
    }

    // Summary
    let unique_count = results.iter().filter(|(info, _)| !info.is_duplicate).count();
    let total_count = results.len();
    
    if cli.mark_duplicates || cli.verbose {
        println!(
            "{}Summary: {} unique certificate(s), {} total occurrence(s){}",
            colors.dim(),
            unique_count,
            total_count,
            colors.reset()
        );
    }
}

/// Format a single certificate from directory scan
fn format_directory_certificate(
    cert_info: &dirscan::CertWithDuplicateInfo,
    parsed: Option<&parser::ParsedCert>,
    cli: &Cli,
    colors: &formatter::Colors,
) {
    use scanner::CertSource;

    let source_label = match &cert_info.cert.source {
        CertSource::DerCandidate { .. } => "DER",
        CertSource::PemBlock { .. } => "PEM",
    };

    // Header
    print!(
        "{}{}Certificate #{}{}",
        colors.bold(),
        colors.bright_cyan(),
        cert_info.global_index,
        colors.reset()
    );

    if cert_info.is_duplicate && cli.mark_duplicates {
        if let Some(ref first) = cert_info.duplicate_of {
            print!(
                " {}{} [duplicate of #{}]{}",
                colors.dim(),
                colors.reset(),
                first.global_index,
                colors.reset()
            );
        }
    }

    println!(
        " {}({}){}",
        colors.dim(),
        source_label,
        colors.reset()
    );

    // Location
    println!(
        "   {}{}File:{} {}{}{}",
        colors.bold(),
        colors.cyan(),
        colors.reset(),
        colors.bright_cyan(),
        cert_info.path.display(),
        colors.reset()
    );
    println!(
        "   {}{}Offset:{} {}0x{:X} ({}){}",
        colors.bold(),
        colors.cyan(),
        colors.reset(),
        colors.bright_cyan(),
        cert_info.cert.offset,
        cert_info.cert.offset,
        colors.reset()
    );
    println!(
        "   {}{}Size:{} {}{} bytes{}",
        colors.bold(),
        colors.cyan(),
        colors.reset(),
        colors.bright_cyan(),
        cert_info.cert.raw_range_len,
        colors.reset()
    );
    println!(
        "   {}{}SHA-256:{} {}{}{}",
        colors.bold(),
        colors.cyan(),
        colors.reset(),
        colors.bright_cyan(),
        cert_info.cert.sha256_hex(),
        colors.reset()
    );

    // Duplicate info
    if cert_info.is_duplicate {
        if cli.mark_duplicates {
            if let Some(ref first) = cert_info.duplicate_of {
                println!();
                println!(
                    "   {}Duplicate Info:{}",
                    colors.dim(),
                    colors.reset()
                );
                println!(
                    "      First seen: {} at offset 0x{:X}",
                    first.path.display(),
                    first.offset
                );
                println!(
                    "      Total occurrences: {}",
                    first.count
                );
            }
        }
    }

    // Parse d certificate details
    if let Some(p) = parsed {
        println!();
        println!(
            "   {}{}Subject:{} {}{}{}",
            colors.bold(),
            colors.cyan(),
            colors.reset(),
            colors.bright_cyan(),
            p.subject,
            colors.reset()
        );
        println!(
            "   {}{}Issuer:{} {}{}{}",
            colors.bold(),
            colors.cyan(),
            colors.reset(),
            colors.bright_cyan(),
            p.issuer,
            colors.reset()
        );
        println!(
            "   {}{}Serial:{} {}{}{}",
            colors.bold(),
            colors.cyan(),
            colors.reset(),
            colors.bright_cyan(),
            p.serial_hex,
            colors.reset()
        );
        println!(
            "   {}{}Valid:{} {}{} to {}{}",
            colors.bold(),
            colors.cyan(),
            colors.reset(),
            colors.bright_cyan(),
            p.not_before.format("%Y-%m-%d %H:%M:%S UTC"),
            p.not_after.format("%Y-%m-%d %H:%M:%S UTC"),
            colors.reset()
        );

        let key_size = if let Some(bits) = p.pubkey_bits {
            format!("{}{} bits{}", colors.green(), bits, colors.reset())
        } else {
            "unknown".to_string()
        };

        println!(
            "   {}{}Public Key:{} {}{} {}",
            colors.bold(),
            colors.cyan(),
            colors.reset(),
            colors.bright_cyan(),
            p.pubkey_algo,
            key_size
        );
        println!(
            "   {}{}Signature:{} {}{}{}",
            colors.bold(),
            colors.cyan(),
            colors.reset(),
            colors.bright_cyan(),
            p.signature_algo,
            colors.reset()
        );
    } else {
        println!();
        println!(
            "   {}Parse failed: invalid or corrupted certificate{}",
            colors.dim(),
            colors.reset()
        );
    }
}

fn extract_certificates(
    cli: &Cli,
    results: &[(scanner::FoundCert, Option<parser::ParsedCert>)],
) -> Result<Vec<PathBuf>> {
    // Check output directory
    if cli.outdir.exists() {
        if !cli.outdir.is_dir() {
            anyhow::bail!("Output path exists but is not a directory: {:?}", cli.outdir);
        }
        if !cli.force && !is_empty_dir(&cli.outdir)? {
            anyhow::bail!(
                "Output directory {:?} is not empty. Use --force to overwrite.",
                cli.outdir
            );
        }
    } else {
        fs::create_dir_all(&cli.outdir)
            .with_context(|| format!("Failed to create output directory: {:?}", cli.outdir))?;
    }

    let mut files = Vec::new();

    // Determine which formats to write
    let write_der = cli.der || (!cli.der && !cli.pem);
    let write_pem = cli.pem || (!cli.der && !cli.pem);

    for (cert, _) in results {
        // Write DER
        if write_der {
            let der_path = cli.outdir.join(format!("cert.{}.der", cert.index));
            fs::write(&der_path, &cert.der)
                .with_context(|| format!("Failed to write DER file: {:?}", der_path))?;
            files.push(der_path.clone());
            if cli.verbose {
                eprintln!("Wrote {}", der_path.display());
            }
        }

        // Write PEM
        if write_pem {
            let pem_path = cli.outdir.join(format!("cert.{}.pem", cert.index));
            write_pem_certificate(&pem_path, &cert.der)?;
            files.push(pem_path.clone());
            if cli.verbose {
                eprintln!("Wrote {}", pem_path.display());
            }
        }
    }

    Ok(files)
}

fn write_pem_certificate(path: &PathBuf, der: &[u8]) -> Result<()> {
    let b64 = STANDARD.encode(der);
    let mut out = String::with_capacity(b64.len() * 4 / 3 + 128);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    fs::write(path, out).with_context(|| format!("Failed to write PEM file: {:?}", path))?;
    Ok(())
}

fn is_empty_dir(path: &PathBuf) -> Result<bool> {
    if !path.is_dir() {
        return Ok(false);
    }
    let mut entries = fs::read_dir(path)?;
    Ok(entries.next().is_none())
}
