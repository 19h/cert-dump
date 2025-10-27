use crate::parser::ParsedCert;
use crate::scanner::{CertSource, FoundCert};
use std::fmt::Write;
use std::path::PathBuf;

// ANSI color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const BRIGHT_CYAN: &str = "\x1b[96m";

pub struct Colors {
    pub enabled: bool,
}

impl Colors {
    pub fn bold(&self) -> &str {
        if self.enabled { BOLD } else { "" }
    }
    pub fn dim(&self) -> &str {
        if self.enabled { DIM } else { "" }
    }
    pub fn reset(&self) -> &str {
        if self.enabled { RESET } else { "" }
    }
    pub fn cyan(&self) -> &str {
        if self.enabled { CYAN } else { "" }
    }
    pub fn green(&self) -> &str {
        if self.enabled { GREEN } else { "" }
    }
    pub fn bright_cyan(&self) -> &str {
        if self.enabled { BRIGHT_CYAN } else { "" }
    }
}

pub fn colors_from_env() -> Colors {
    let enabled = atty::is(atty::Stream::Stdout) && std::env::var("NO_COLOR").is_err();
    Colors { enabled }
}

pub fn format_certificate_list(
    certs: &[(FoundCert, Option<ParsedCert>)],
    output_files: Option<&Vec<PathBuf>>,
    verbose: bool,
) -> String {
    let colors = colors_from_env();
    let mut out = String::new();
    
    if certs.is_empty() {
        writeln!(out, "{}No certificates found.{}", colors.dim(), colors.reset()).unwrap();
        return out;
    }
    
    // Header
    writeln!(
        out,
        "{}{}Certificate Scan Results{}",
        colors.bold(),
        colors.bright_cyan(),
        colors.reset()
    )
    .unwrap();
    writeln!(out, "{}{}{}", colors.cyan(), "=".repeat(50), colors.reset()).unwrap();
    writeln!(out).unwrap();
    
    for (cert, parsed_opt) in certs {
        format_certificate(&mut out, cert, parsed_opt.as_ref(), &colors, verbose);
        writeln!(out).unwrap();
    }
    
    // Output files section
    if let Some(files) = output_files {
        if !files.is_empty() {
            writeln!(
                out,
                "{}{}Output Files{}",
                colors.bold(),
                colors.bright_cyan(),
                colors.reset()
            )
            .unwrap();
            
            for (i, path) in files.iter().enumerate() {
                let label = if path.extension().and_then(|s| s.to_str()) == Some("der") {
                    format!("Certificate {} (DER)", i / 2)
                } else {
                    format!("Certificate {} (PEM)", i / 2)
                };
                writeln!(
                    out,
                    "   {}{}{}{}: {}{}{}",
                    colors.bold(),
                    colors.cyan(),
                    label,
                    colors.reset(),
                    colors.bright_cyan(),
                    path.display(),
                    colors.reset()
                )
                .unwrap();
            }
        }
    }
    
    out
}

fn format_certificate(
    out: &mut String,
    cert: &FoundCert,
    parsed: Option<&ParsedCert>,
    colors: &Colors,
    verbose: bool,
) {
    // Header with index and source
    let source_label = match &cert.source {
        CertSource::DerCandidate { .. } => "DER",
        CertSource::PemBlock { .. } => "PEM",
    };
    
    writeln!(
        out,
        "{}{}Certificate {}{} {}({}){}", 
        colors.bold(),
        colors.bright_cyan(),
        cert.index,
        colors.reset(),
        colors.dim(),
        source_label,
        colors.reset()
    )
    .unwrap();
    
    // Location block
    let pairs = vec![
        ("Offset", format!("0x{:X} ({})", cert.offset, cert.offset)),
        ("Size", format!("{} bytes", cert.raw_range_len)),
    ];
    render_kv_block(out, &pairs, 3, colors);
    writeln!(out).unwrap();
    
    if let Some(p) = parsed {
        // Subject/Issuer block
        let pairs = vec![
            ("Subject", p.subject.clone()),
            ("Issuer", p.issuer.clone()),
            ("Serial", p.serial_hex.clone()),
        ];
        render_kv_block(out, &pairs, 3, colors);
        writeln!(out).unwrap();
        
        // Validity block
        let pairs = vec![
            ("Not Before", format!("{}", p.not_before.format("%Y-%m-%d %H:%M:%S UTC"))),
            ("Not After", format!("{}", p.not_after.format("%Y-%m-%d %H:%M:%S UTC"))),
        ];
        render_kv_block(out, &pairs, 3, colors);
        writeln!(out).unwrap();
        
        // Public Key block
        let key_size = if let Some(bits) = p.pubkey_bits {
            format!("{}{} bits{}", colors.green(), bits, colors.reset())
        } else {
            "unknown".to_string()
        };
        
        let pairs = vec![
            ("Algorithm", p.pubkey_algo.clone()),
            ("Key Size", key_size),
        ];
        render_kv_block(out, &pairs, 3, colors);
        writeln!(out).unwrap();
        
        // Signature block
        let pairs = vec![
            ("Algorithm", p.signature_algo.clone()),
        ];
        render_kv_block(out, &pairs, 3, colors);
        
        // Verbose info
        if verbose {
            writeln!(out).unwrap();
            writeln!(out, "   {}Verbose Details:{}", colors.dim(), colors.reset()).unwrap();
            writeln!(
                out,
                "      {}DER size: {} bytes{}", 
                colors.dim(),
                cert.der.len(),
                colors.reset()
            )
            .unwrap();
            if let CertSource::PemBlock { header_offset, footer_offset } = &cert.source {
                writeln!(
                    out,
                    "      {}PEM header: 0x{:X}, footer: 0x{:X}{}", 
                    colors.dim(),
                    header_offset,
                    footer_offset,
                    colors.reset()
                )
                .unwrap();
            }
        }
    } else {
        writeln!(
            out,
            "   {}Parse failed: invalid or corrupted certificate{}",
            colors.dim(),
            colors.reset()
        )
        .unwrap();
    }
}

fn render_kv_block(out: &mut String, pairs: &[(&str, String)], indent: usize, colors: &Colors) {
    if pairs.is_empty() {
        return;
    }
    
    let indent_str = " ".repeat(indent);
    
    for (key, value) in pairs {
        writeln!(
            out,
            "{}{}{}{}{}: {}{}{}",
            indent_str,
            colors.bold(),
            colors.cyan(),
            key,
            colors.reset(),
            colors.bright_cyan(),
            value,
            colors.reset()
        )
        .unwrap();
    }
}
