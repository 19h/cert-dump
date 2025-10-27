use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::Parser;
use std::fs;
use std::path::PathBuf;

mod formatter;
mod parser;
mod scanner;

use formatter::format_certificate_list;
use parser::parse_certificate;
use scanner::scan_certificates;

/// High-performance X.509 certificate scanner and extractor.
#[derive(Parser, Debug)]
#[command(name = "cert-dump", version = "0.1.0")]
#[command(about = "Scans binaries for X.509 certificates (DER and PEM) and optionally extracts them")]
struct Cli {
    /// Binary file to scan
    #[arg(value_name = "BINARY_FILE")]
    input: PathBuf,

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Read the binary file
    let data = fs::read(&cli.input)
        .with_context(|| format!("Failed to read input file: {:?}", cli.input))?;

    if cli.verbose {
        eprintln!("Scanning {} bytes from {:?}...", data.len(), cli.input);
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
