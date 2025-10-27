use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use memchr::{memchr_iter, memmem};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub enum CertSource {
    DerCandidate { tlv_len: usize },
    PemBlock { header_offset: usize, footer_offset: usize },
}

#[derive(Debug, Clone)]
pub struct FoundCert {
    pub index: usize,
    pub offset: usize,
    pub raw_range_len: usize,
    pub der: Vec<u8>,
    pub source: CertSource,
}

const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const PEM_END: &[u8] = b"-----END CERTIFICATE-----";

pub fn scan_certificates(data: &[u8], verbose: bool) -> Result<Vec<FoundCert>> {
    let mut out = Vec::new();
    
    scan_pem(data, &mut out, verbose)?;
    scan_der(data, &mut out, verbose)?;
    
    // Sort by offset and assign indices
    out.sort_by_key(|c| c.offset);
    for (i, c) in out.iter_mut().enumerate() {
        c.index = i;
    }
    
    Ok(out)
}

fn scan_pem(data: &[u8], out: &mut Vec<FoundCert>, verbose: bool) -> Result<()> {
    let finder = memmem::Finder::new(PEM_BEGIN);
    let mut pos = 0;
    
    while pos < data.len() {
        if let Some(begin_offset) = finder.find(&data[pos..]) {
            let begin_abs = pos + begin_offset;
            
            // Search for END marker after BEGIN
            let search_start = begin_abs + PEM_BEGIN.len();
            if search_start >= data.len() {
                break;
            }
            
            let end_finder = memmem::Finder::new(PEM_END);
            if let Some(end_rel) = end_finder.find(&data[search_start..]) {
                let end_abs = search_start + end_rel;
                let footer_end = end_abs + PEM_END.len();
                
                // Extract body between header and footer
                let body_start = begin_abs + PEM_BEGIN.len();
                let body_data = &data[body_start..end_abs];
                
                // Clean the body: remove lines starting with ----- and whitespace-only lines
                let cleaned = body_data
                    .split(|&b| b == b'\n' || b == b'\r')
                    .filter(|line| {
                        let trimmed = line.iter().filter(|&&b| b != b' ' && b != b'\t').copied().collect::<Vec<_>>();
                        !trimmed.is_empty() && !trimmed.starts_with(b"-----")
                    })
                    .flat_map(|line| line.iter().copied())
                    .collect::<Vec<u8>>();
                
                // Decode base64
                match STANDARD.decode(&cleaned) {
                    Ok(der) => {
                        let raw_range_len = footer_end - begin_abs;
                        out.push(FoundCert {
                            index: 0, // Will be assigned later
                            offset: begin_abs,
                            raw_range_len,
                            der,
                            source: CertSource::PemBlock {
                                header_offset: begin_abs,
                                footer_offset: end_abs,
                            },
                        });
                        if verbose {
                            eprintln!("PEM cert found at offset 0x{:X} ({} bytes)", begin_abs, raw_range_len);
                        }
                    }
                    Err(e) => {
                        if verbose {
                            eprintln!("Warning: PEM decode failed at offset 0x{:X}: {}", begin_abs, e);
                        }
                    }
                }
                
                // Continue search after this PEM block
                pos = footer_end;
            } else {
                // No matching END found, skip this BEGIN
                pos = begin_abs + 1;
            }
        } else {
            break;
        }
    }
    
    Ok(())
}

fn scan_der(data: &[u8], out: &mut Vec<FoundCert>, verbose: bool) -> Result<()> {
    let mut seen = HashSet::new();
    
    for i in memchr_iter(0x30, data) {
        if i + 2 > data.len() {
            continue;
        }
        
        // Parse DER length encoding
        let b0 = data[i];
        let b1 = data[i + 1];
        
        if b0 != 0x30 {
            continue;
        }
        
        let (header_len, content_len) = if b1 & 0x80 == 0 {
            // Short form
            (2, b1 as usize)
        } else {
            // Long form
            let n = (b1 & 0x7F) as usize;
            if n == 0 || n >= 5 || i + 2 + n > data.len() {
                continue;
            }
            
            // Read n bytes as big-endian length
            let mut len_val = 0usize;
            let len_bytes = &data[i + 2..i + 2 + n];
            
            // Check for leading zero (invalid in DER)
            if len_bytes[0] == 0 {
                continue;
            }
            
            for &byte in len_bytes {
                len_val = len_val.checked_mul(256).and_then(|v| v.checked_add(byte as usize)).unwrap_or(0);
                if len_val == 0 {
                    continue;
                }
            }
            
            if len_val < 3 {
                continue;
            }
            
            (2 + n, len_val)
        };
        
        let total_len = header_len + content_len;
        if i + total_len > data.len() {
            continue;
        }
        
        // Check if already seen
        if !seen.insert((i, total_len)) {
            continue;
        }
        
        // Light validation with x509-parser
        let candidate = &data[i..i + total_len];
        if let Ok((_rem, _cert)) = x509_parser::parse_x509_certificate(candidate) {
            out.push(FoundCert {
                index: 0, // Will be assigned later
                offset: i,
                raw_range_len: total_len,
                der: candidate.to_vec(),
                source: CertSource::DerCandidate { tlv_len: total_len },
            });
            if verbose {
                eprintln!("DER cert found at offset 0x{:X} ({} bytes)", i, total_len);
            }
        }
    }
    
    Ok(())
}
