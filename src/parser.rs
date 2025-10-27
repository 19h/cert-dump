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
        // RSA PKCS#1 v1.5 with hash functions
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.14" => "sha224WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        
        // RSA-PSS (parameterized)
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        
        // DSA with hash functions
        "1.2.840.10040.4.3" => "dsa-with-sha1",
        "2.16.840.1.101.3.4.3.1" => "dsa-with-sha224",
        "2.16.840.1.101.3.4.3.2" => "dsa-with-sha256",
        
        // ECDSA with hash functions
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.1" => "ecdsa-with-SHA224",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        
        // Modern elliptic curves (EdDSA)
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        
        // Chinese national standards (SM series)
        "1.2.156.10197.1.501" => "sm2sign-with-sm3",
        
        // Russian national standards (GOST R 34.10-2012)
        "1.2.643.7.1.1.3.2" => "id-tc26-signwithdigest-gost3410-12-256",
        "1.2.643.7.1.1.3.3" => "id-tc26-signwithdigest-gost3410-12-512",
        
        // Post-quantum cryptography (NIST-selected algorithms)
        // CRYSTALS-Dilithium (ML-DSA)
        "2.16.840.1.101.3.4.3.17" => "ML-DSA-44",
        "2.16.840.1.101.3.4.3.18" => "ML-DSA-65",
        "2.16.840.1.101.3.4.3.19" => "ML-DSA-87",
        // Provisional OIDs for Dilithium Round 3
        "1.3.6.1.4.1.2.267.7.6.5" => "CRYSTALS-Dilithium(6,5)-R3",
        
        _ => "unknown",
    }
}

fn map_pubkey_oid(oid: &Oid) -> &'static str {
    let s = oid.to_id_string();
    match s.as_str() {
        // RSA
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.2.840.113549.1.1.7" => "RSA-OAEP",
        
        // DSA
        "1.2.840.10040.4.1" => "DSA",
        
        // Elliptic Curve
        "1.2.840.10045.2.1" => "EC",
        
        // Modern curves (X25519/X448 for ECDH, Ed25519/Ed448 for signatures)
        "1.3.101.110" => "X25519",
        "1.3.101.111" => "X448",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        
        // Chinese national standards
        "1.2.156.10197.1.301" => "SM2",
        
        // Russian national standards (GOST R 34.10-2012)
        "1.2.643.7.1.1.1.1" => "id-tc26-gost3410-12-256",
        "1.2.643.7.1.1.1.2" => "id-tc26-gost3410-12-512",
        
        // Post-quantum cryptography (NIST-selected algorithms)
        // CRYSTALS-Dilithium (ML-DSA) - signatures
        "2.16.840.1.101.3.4.3.17" => "ML-DSA-44",
        "2.16.840.1.101.3.4.3.18" => "ML-DSA-65",
        "2.16.840.1.101.3.4.3.19" => "ML-DSA-87",
        // Provisional OIDs for Dilithium
        "1.3.6.1.4.1.2.267.7.6.5" => "CRYSTALS-Dilithium(6,5)-R3",
        
        // CRYSTALS-Kyber (ML-KEM) - key encapsulation
        "1.3.6.1.4.1.22554.5.6.1" => "ML-KEM-512",
        "1.3.6.1.4.1.22554.5.6.2" => "ML-KEM-768",
        "1.3.6.1.4.1.22554.5.6.3" => "ML-KEM-1024",
        // Provisional OIDs for Kyber Round 3
        "1.3.6.1.4.1.2.267.8.4.4" => "CRYSTALS-Kyber(1024)-R3",
        
        _ => "unknown",
    }
}

fn extract_key_bits(spki: &SubjectPublicKeyInfo) -> Option<u32> {
    let algo_str = spki.algorithm.algorithm.to_id_string();
    
    match algo_str.as_str() {
        // RSA algorithms
        "1.2.840.113549.1.1.1" |  // rsaEncryption
        "1.2.840.113549.1.1.10" | // RSASSA-PSS
        "1.2.840.113549.1.1.7" => { // RSAES-OAEP
            rsa_bits_from_spki(spki)
        }
        
        // Elliptic Curve
        "1.2.840.10045.2.1" => {
            ec_bits_from_params(spki)
        }
        
        // Modern elliptic curves with fixed sizes
        "1.3.101.110" => Some(255), // X25519 (Curve25519 for ECDH)
        "1.3.101.111" => Some(448), // X448 (Curve448 for ECDH)
        "1.3.101.112" => Some(255), // Ed25519 (Curve25519 for signatures)
        "1.3.101.113" => Some(448), // Ed448 (Curve448 for signatures)
        
        // Chinese SM2 (elliptic curve)
        "1.2.156.10197.1.301" => Some(256), // SM2 uses 256-bit curve
        
        // Russian GOST R 34.10-2012 (elliptic curve)
        "1.2.643.7.1.1.1.1" => Some(256), // GOST 34.10-2012 256-bit
        "1.2.643.7.1.1.1.2" => Some(512), // GOST 34.10-2012 512-bit
        
        // Post-quantum cryptography
        // CRYSTALS-Dilithium (ML-DSA) - public key sizes in bits
        "2.16.840.1.101.3.4.3.17" => Some(1312), // ML-DSA-44 public key size
        "2.16.840.1.101.3.4.3.18" => Some(1952), // ML-DSA-65 public key size
        "2.16.840.1.101.3.4.3.19" => Some(2592), // ML-DSA-87 public key size
        "1.3.6.1.4.1.2.267.7.6.5" => Some(1952), // Dilithium(6,5) R3 public key size
        
        // CRYSTALS-Kyber (ML-KEM) - security levels
        "1.3.6.1.4.1.22554.5.6.1" => Some(512),  // ML-KEM-512 (NIST Level 1)
        "1.3.6.1.4.1.22554.5.6.2" => Some(768),  // ML-KEM-768 (NIST Level 3)
        "1.3.6.1.4.1.22554.5.6.3" => Some(1024), // ML-KEM-1024 (NIST Level 5)
        "1.3.6.1.4.1.2.267.8.4.4" => Some(1024), // Kyber1024 R3
        
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
    let params = spki.algorithm.parameters.as_ref()?;
    
    // Parse the curve OID from the parameters
    if let Ok(oid) = params.as_oid() {
        let curve_str = oid.to_id_string();
        return match curve_str.as_str() {
            // NIST/ANSI X9.62 prime curves (P-curves)
            "1.2.840.10045.3.1.1" => Some(192),  // secp192r1 / P-192 / prime192v1
            "1.3.132.0.33" => Some(224),         // secp224r1 / P-224
            "1.2.840.10045.3.1.7" => Some(256),  // secp256r1 / P-256 / prime256v1
            "1.3.132.0.34" => Some(384),         // secp384r1 / P-384
            "1.3.132.0.35" => Some(521),         // secp521r1 / P-521
            
            // SECG curves
            "1.3.132.0.10" => Some(256),         // secp256k1 (Bitcoin curve)
            
            // Brainpool curves (RFC 5639)
            "1.3.36.3.3.2.8.1.1.7" => Some(256), // brainpoolP256r1
            "1.3.36.3.3.2.8.1.1.11" => Some(384), // brainpoolP384r1
            "1.3.36.3.3.2.8.1.1.13" => Some(512), // brainpoolP512r1
            
            // Chinese national standard
            "1.2.156.10197.1.301" => Some(256),  // sm2p256v1
            
            // Russian GOST elliptic curves
            "1.2.643.7.1.2.1.1.1" => Some(256),  // GOST R 34.10-2012 256-bit curve
            "1.2.643.7.1.2.1.2.1" => Some(512),  // GOST R 34.10-2012 512-bit curve
            
            _ => None,
        };
    }
    
    None
}
