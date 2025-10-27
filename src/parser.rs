use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use der_parser::oid::Oid;
use x509_parser::{prelude::*, time::ASN1Time};

#[derive(Debug, Clone)]
pub struct ParsedCert {
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub pubkey_algo: String,
    pub pubkey_bits: Option<u32>,
    pub signature_algo: String,
    pub extra_debug: Option<String>,
}

pub fn parse_certificate(der: &[u8]) -> Result<ParsedCert> {
    let (_rem, cert) = x509_parser::parse_x509_certificate(der)
        .context("Failed to parse X.509 certificate")?;
    
    let tbs = &cert.tbs_certificate;
    
    // Extract subject and issuer
    let subject = format_dn(&tbs.subject);
    let issuer = format_dn(&tbs.issuer);
    
    // Extract serial number
    let serial_hex = serial_to_hex(&tbs.serial.to_bytes_be());
    
    // Extract validity dates
    let not_before = as_chrono_time(&tbs.validity.not_before)?;
    let not_after = as_chrono_time(&tbs.validity.not_after)?;
    
    // Extract signature algorithm
    let signature_algo = map_signature_oid(&cert.signature_algorithm.algorithm);
    
    // Extract public key algorithm and size
    let spki = &tbs.subject_pki;
    let pubkey_algo = map_pubkey_oid(&spki.algorithm.algorithm);
    let pubkey_bits = extract_key_bits(spki);
    
    let extra_debug = None; // Can be populated with additional info in verbose mode
    
    Ok(ParsedCert {
        subject,
        issuer,
        serial_hex,
        not_before,
        not_after,
        pubkey_algo: pubkey_algo.to_string(),
        pubkey_bits,
        signature_algo: signature_algo.to_string(),
        extra_debug,
    })
}

fn format_dn(name: &X509Name) -> String {
    let mut parts = Vec::new();
    
    // Extract attributes in preferred order
    if let Some(cn) = name.iter_common_name().find_map(|v| v.as_str().ok()) {
        parts.push(format!("CN={}", cn.trim()));
    }
    
    if let Some(ou) = name.iter_organizational_unit().find_map(|v| v.as_str().ok()) {
        parts.push(format!("OU={}", ou.trim()));
    }
    
    if let Some(o) = name.iter_organization().find_map(|v| v.as_str().ok()) {
        parts.push(format!("O={}", o.trim()));
    }
    
    if let Some(l) = name.iter_locality().find_map(|v| v.as_str().ok()) {
        parts.push(format!("L={}", l.trim()));
    }
    
    if let Some(st) = name.iter_state_or_province().find_map(|v| v.as_str().ok()) {
        parts.push(format!("ST={}", st.trim()));
    }
    
    if let Some(c) = name.iter_country().find_map(|v| v.as_str().ok()) {
        parts.push(format!("C={}", c.trim()));
    }
    
    if let Some(email) = name.iter_email().find_map(|v| v.as_str().ok()) {
        parts.push(format!("emailAddress={}", email.trim()));
    }
    
    if parts.is_empty() {
        // Fallback: iterate all attributes
        for rdn in name.iter() {
            for attr in rdn.iter() {
                if let Ok(val) = attr.as_str() {
                    let oid_str = attr.attr_type().to_id_string();
                    parts.push(format!("{}={}", oid_str, val.trim()));
                }
            }
        }
    }
    
    if parts.is_empty() {
        "(empty)".to_string()
    } else {
        parts.join(", ")
    }
}

fn serial_to_hex(serial: &[u8]) -> String {
    serial.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join("")
}

fn as_chrono_time(t: &ASN1Time) -> Result<DateTime<Utc>> {
    let unix_ts = t.timestamp();
    Ok(DateTime::from_timestamp(unix_ts, 0)
        .context("Invalid timestamp")?)
}

fn map_signature_oid(oid: &Oid) -> &'static str {
    let s = oid.to_id_string();
    match s.as_str() {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        _ => "unknown",
    }
}

fn map_pubkey_oid(oid: &Oid) -> &'static str {
    let s = oid.to_id_string();
    match s.as_str() {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.10045.2.1" => "EC",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        _ => "unknown",
    }
}

fn extract_key_bits(spki: &SubjectPublicKeyInfo) -> Option<u32> {
    let algo_str = spki.algorithm.algorithm.to_id_string();
    
    match algo_str.as_str() {
        "1.2.840.113549.1.1.1" => {
            // RSA: parse the BIT STRING to get modulus
            rsa_bits_from_spki(spki)
        }
        "1.2.840.10045.2.1" => {
            // EC: get curve from parameters
            ec_bits_from_params(spki)
        }
        "1.3.101.112" => Some(256), // Ed25519
        "1.3.101.113" => Some(456), // Ed448
        _ => None,
    }
}

fn rsa_bits_from_spki(spki: &SubjectPublicKeyInfo) -> Option<u32> {
    // Parse the BIT STRING content as RSAPublicKey (SEQUENCE { n INTEGER, e INTEGER })
    let data = &spki.subject_public_key.data;
    
    if let Ok((_, seq)) = der_parser::parse_der(data) {
        if let der_parser::der::DerObjectContent::Sequence(ref items) = seq.content {
            if let Some(first) = items.first() {
                if let der_parser::der::DerObjectContent::Integer(n_bytes) = &first.content {
                    // Count bits in modulus
                    let bit_len = n_bytes.len() * 8;
                    // Subtract leading zero bits
                    let leading_zeros = n_bytes.iter().take_while(|&&b| b == 0).count() * 8;
                    let first_nonzero = n_bytes.iter().skip_while(|&&b| b == 0).next();
                    let additional_zeros = if let Some(&byte) = first_nonzero {
                        byte.leading_zeros() as usize
                    } else {
                        0
                    };
                    let actual_bits = bit_len - leading_zeros - additional_zeros;
                    return Some(actual_bits as u32);
                }
            }
        }
    }
    
    None
}

fn ec_bits_from_params(spki: &SubjectPublicKeyInfo) -> Option<u32> {
    // EC parameters contain the curve OID
    let params_bytes = spki.algorithm.parameters.as_ref()?;
    if let Ok((_,params)) = der_parser::parse_der(params_bytes.as_bytes()) {
        if let der_parser::der::DerObjectContent::OID(oid) = params.content {
            let curve_str = oid.to_id_string();
            return match curve_str.as_str() {
                "1.2.840.10045.3.1.7" => Some(256),  // prime256v1 (P-256)
                "1.3.132.0.34" => Some(384),         // secp384r1
                "1.3.132.0.35" => Some(521),         // secp521r1
                _ => None,
            };
        }
    }
    
    None
}
