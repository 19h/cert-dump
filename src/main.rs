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
mod filter;
mod tree;

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

    // Filtering options
    /// Filter by organization (O) - can be specified multiple times
    #[arg(long = "org")]
    org: Vec<String>,

    /// Filter by organizational unit (OU) - can be specified multiple times
    #[arg(long = "ou")]
    ou: Vec<String>,

    /// Filter by common name (CN) - can be specified multiple times
    #[arg(long = "common")]
    common: Vec<String>,

    /// Filter by country (C) - can be specified multiple times
    #[arg(long = "country")]
    country: Vec<String>,

    /// Filter by locality (L) - can be specified multiple times
    #[arg(long = "locality")]
    locality: Vec<String>,

    /// Filter by state (ST) - can be specified multiple times
    #[arg(long = "state")]
    state: Vec<String>,

    /// Filter by serial number (substring match) - can be specified multiple times
    #[arg(long = "serial")]
    serial: Vec<String>,

    /// Filter by subject DN (substring match) - can be specified multiple times
    #[arg(long = "subject")]
    subject: Vec<String>,

    /// Filter by issuer DN (substring match) - can be specified multiple times
    #[arg(long = "issuer")]
    issuer: Vec<String>,

    /// Filter by public key algorithm (fuzzy: rsa, ec, sha256, etc.) - can be specified multiple times
    #[arg(long = "key-algo")]
    key_algo: Vec<String>,

    /// Filter by signature algorithm (fuzzy: rsa, sha256, ecdsa, etc.) - can be specified multiple times
    #[arg(long = "sig-algo")]
    sig_algo: Vec<String>,

    /// Filter by public key size in bits - can be specified multiple times
    #[arg(long = "key-size")]
    key_size: Vec<u32>,

    /// Show only expired certificates
    #[arg(long = "expired")]
    expired: bool,

    /// Show only currently valid certificates
    #[arg(long = "valid")]
    valid: bool,

    /// Filter by SHA-256 fingerprint (substring match) - can be specified multiple times
    #[arg(long = "sha256")]
    sha256_filter: Vec<String>,

    /// Display certificates in tree format showing signing relationships
    #[arg(long = "tree")]
    tree: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Build filter from CLI arguments
    let filter = build_filter(&cli);

    // Determine if we're in single-file or multi-file mode
    let is_single_file = cli.input.len() == 1 
        && cli.input[0].is_file() 
        && !cli.recursive
        && !cli.unique_only
        && !cli.mark_duplicates;

    if is_single_file {
        // Traditional single-file mode (preserves existing behavior)
        run_single_file_mode(&cli, &filter)?;
    } else {
        // Directory/multi-file mode with deduplication
        run_directory_mode(&cli, &filter)?;
    }

    Ok(())
}

/// Build certificate filter from CLI arguments
fn build_filter(cli: &Cli) -> filter::CertFilter {
    filter::CertFilter {
        organizations: cli.org.clone(),
        organizational_units: cli.ou.clone(),
        common_names: cli.common.clone(),
        countries: cli.country.clone(),
        localities: cli.locality.clone(),
        states: cli.state.clone(),
        serials: cli.serial.clone(),
        subjects: cli.subject.clone(),
        issuers: cli.issuer.clone(),
        key_algorithms: cli.key_algo.clone(),
        signature_algorithms: cli.sig_algo.clone(),
        key_sizes: cli.key_size.clone(),
        expired_only: cli.expired,
        valid_only: cli.valid,
        not_before: None, // Can be extended later with date parsing
        not_after: None,  // Can be extended later with date parsing
        sha256: cli.sha256_filter.clone(),
    }
}

/// Traditional single-file scanning mode
fn run_single_file_mode(cli: &Cli, filter: &filter::CertFilter) -> Result<()> {
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

    // Parse each certificate and apply filter
    let mut results = Vec::new();
    let mut filtered_count = 0;
    
    for cert in found_certs {
        let parsed = parse_certificate(&cert.der).ok();
        if parsed.is_none() && cli.verbose {
            eprintln!("Warning: Failed to parse certificate at offset 0x{:X}", cert.offset);
        }
        
        // Apply filter
        let passes_filter = if let Some(ref p) = parsed {
            filter.matches(p, &cert.sha256_hex())
        } else {
            // If parsing failed, only include if no filters are set
            filter.is_empty()
        };
        
        if passes_filter {
            results.push((cert, parsed));
        } else {
            filtered_count += 1;
        }
    }
    
    if cli.verbose && filtered_count > 0 {
        eprintln!("Filtered out {} certificate(s) that didn't match criteria", filtered_count);
    }

    // Extract certificates if --dump is specified
    let mut output_files = None;
    if cli.dump {
        output_files = Some(extract_certificates(&cli, &results)?);
    } else if (cli.der || cli.pem) && cli.verbose {
        eprintln!("Note: --der/--pem flags ignored without --dump");
    }

    // Print formatted output
    if cli.tree {
        use formatter::colors_from_env;
        let colors = colors_from_env();
        let roots = tree::build_tree(&results);
        tree::print_tree(&results, &roots, &colors);
    } else {
        let formatted = format_certificate_list(&results, output_files.as_ref(), cli.verbose);
        print!("{}", formatted);
    }

    Ok(())
}

/// Directory/multi-file scanning mode with duplicate detection
fn run_directory_mode(cli: &Cli, filter: &filter::CertFilter) -> Result<()> {
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
    let mut filtered_count = 0;

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

        // Apply filter
        let passes_filter = if let Some(ref p) = parsed {
            filter.matches(p, &cert_info.cert.sha256_hex())
        } else {
            // If parsing failed, only include if no filters are set
            filter.is_empty()
        };
        
        if passes_filter {
            all_results.push((cert_info, parsed));
        } else {
            filtered_count += 1;
        }
        
        Ok(())
    })?;
    
    if cli.verbose && filtered_count > 0 {
        eprintln!("Filtered out {} certificate(s) that didn't match criteria", filtered_count);
    }

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

    // Extract certificates if --dump is specified
    let mut output_files = None;
    if cli.dump {
        output_files = Some(extract_certificates_from_directory(&cli, &all_results)?);
    } else if (cli.der || cli.pem) && cli.verbose {
        eprintln!("Note: --der/--pem flags ignored without --dump");
    }

    // Output results based on format
    if cli.json {
        output_json(&all_results)?;
    } else if cli.tree {
        use formatter::colors_from_env;
        let colors = colors_from_env();
        let roots = tree::build_tree(&all_results);
        tree::print_tree(&all_results, &roots, &colors);
    } else {
        format_directory_results(&all_results, cli, output_files.as_ref());
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
    output_files: Option<&Vec<PathBuf>>,
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

    // Output files section
    if let Some(files) = output_files {
        if !files.is_empty() {
            println!();
            println!(
                "{}{}Output Files{}",
                colors.bold(),
                colors.bright_cyan(),
                colors.reset()
            );
            println!("{}{}{}", colors.cyan(), "=".repeat(50), colors.reset());
            println!();
            
            for path in files {
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                let label = if ext == "der" { "DER" } else { "PEM" };
                println!(
                    "   {}{}{}{}: {}{}{}",
                    colors.bold(),
                    colors.cyan(),
                    label,
                    colors.reset(),
                    colors.bright_cyan(),
                    path.display(),
                    colors.reset()
                );
            }
        }
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

/// Extract certificates from directory scan results
fn extract_certificates_from_directory(
    cli: &Cli,
    results: &[(dirscan::CertWithDuplicateInfo, Option<parser::ParsedCert>)],
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

    for (cert_info, _) in results {
        let index = cert_info.global_index;
        
        // Write DER
        if write_der {
            let der_path = cli.outdir.join(format!("cert.{}.der", index));
            fs::write(&der_path, &cert_info.cert.der)
                .with_context(|| format!("Failed to write DER file: {:?}", der_path))?;
            files.push(der_path.clone());
            if cli.verbose {
                eprintln!("Wrote {}", der_path.display());
            }
        }

        // Write PEM
        if write_pem {
            let pem_path = cli.outdir.join(format!("cert.{}.pem", index));
            write_pem_certificate(&pem_path, &cert_info.cert.der)?;
            files.push(pem_path.clone());
            if cli.verbose {
                eprintln!("Wrote {}", pem_path.display());
            }
        }
    }

    Ok(files)
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
