use serde::Serialize;
use std::path::PathBuf;

use crate::dirscan::{CertWithDuplicateInfo, FirstSeen};
use crate::parser::ParsedCert;
use crate::scanner::CertSource;

/// JSON representation of a certificate with duplicate information
#[derive(Debug, Serialize)]
pub struct JsonCertificate {
    pub global_index: u64,
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub offset: usize,
    pub size: usize,
    pub sha256: String,
    pub source: String,
    pub is_duplicate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplicate_of: Option<JsonDuplicateInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_bits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
}

/// JSON representation of duplicate information
#[derive(Debug, Serialize)]
pub struct JsonDuplicateInfo {
    pub sha256: String,
    pub global_index: u64,
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub offset: usize,
    pub size: usize,
    pub occurrences: u64,
}

/// Serialize PathBuf as string for JSON
fn serialize_path<S>(path: &PathBuf, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&path.display().to_string())
}

impl JsonCertificate {
    /// Create a JSON certificate from directory scan result
    pub fn from_directory_scan(
        cert_info: &CertWithDuplicateInfo,
        parsed: Option<&ParsedCert>,
    ) -> Self {
        let source = match &cert_info.cert.source {
            CertSource::DerCandidate { .. } => "DER".to_string(),
            CertSource::PemBlock { .. } => "PEM".to_string(),
        };

        let duplicate_of = cert_info.duplicate_of.as_ref().map(|first| {
            JsonDuplicateInfo {
                sha256: cert_info.cert.sha256_hex(),
                global_index: first.global_index,
                path: first.path.clone(),
                offset: first.offset,
                size: first.size,
                occurrences: first.count,
            }
        });

        Self {
            global_index: cert_info.global_index,
            path: cert_info.path.clone(),
            offset: cert_info.cert.offset,
            size: cert_info.cert.raw_range_len,
            sha256: cert_info.cert.sha256_hex(),
            source,
            is_duplicate: cert_info.is_duplicate,
            duplicate_of,
            subject: parsed.map(|p| p.subject.clone()),
            issuer: parsed.map(|p| p.issuer.clone()),
            serial: parsed.map(|p| p.serial_hex.clone()),
            not_before: parsed.map(|p| p.not_before.to_rfc3339()),
            not_after: parsed.map(|p| p.not_after.to_rfc3339()),
            public_key_algorithm: parsed.map(|p| p.pubkey_algo.clone()),
            public_key_bits: parsed.and_then(|p| p.pubkey_bits),
            signature_algorithm: parsed.map(|p| p.signature_algo.clone()),
        }
    }
}
