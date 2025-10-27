use chrono::{DateTime, Utc};
use crate::parser::ParsedCert;

/// Certificate filter configuration
#[derive(Debug, Clone, Default)]
pub struct CertFilter {
    pub organizations: Vec<String>,
    pub organizational_units: Vec<String>,
    pub common_names: Vec<String>,
    pub countries: Vec<String>,
    pub localities: Vec<String>,
    pub states: Vec<String>,
    pub serials: Vec<String>,
    pub subjects: Vec<String>,
    pub issuers: Vec<String>,
    pub key_algorithms: Vec<String>,
    pub signature_algorithms: Vec<String>,
    pub key_sizes: Vec<u32>,
    pub expired_only: bool,
    pub valid_only: bool,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub sha256: Vec<String>,
}

impl CertFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if the filter is empty (no filters applied)
    pub fn is_empty(&self) -> bool {
        self.organizations.is_empty()
            && self.organizational_units.is_empty()
            && self.common_names.is_empty()
            && self.countries.is_empty()
            && self.localities.is_empty()
            && self.states.is_empty()
            && self.serials.is_empty()
            && self.subjects.is_empty()
            && self.issuers.is_empty()
            && self.key_algorithms.is_empty()
            && self.signature_algorithms.is_empty()
            && self.key_sizes.is_empty()
            && !self.expired_only
            && !self.valid_only
            && self.not_before.is_none()
            && self.not_after.is_none()
            && self.sha256.is_empty()
    }

    /// Apply the filter to a certificate
    pub fn matches(&self, cert: &ParsedCert, sha256: &str) -> bool {
        // If no filters, match everything
        if self.is_empty() {
            return true;
        }

        // SHA-256 filter (exact match, case-insensitive)
        if !self.sha256.is_empty() {
            if !self.sha256.iter().any(|filter| {
                sha256.eq_ignore_ascii_case(filter) || sha256.contains(&filter.to_lowercase())
            }) {
                return false;
            }
        }

        // Organization filter (fuzzy)
        if !self.organizations.is_empty() {
            if !self.organizations.iter().any(|org| {
                fuzzy_match(&cert.subject, org) || fuzzy_match(&cert.issuer, org)
            }) {
                return false;
            }
        }

        // Organizational Unit filter (fuzzy)
        if !self.organizational_units.is_empty() {
            if !self.organizational_units.iter().any(|ou| {
                fuzzy_match(&cert.subject, ou) || fuzzy_match(&cert.issuer, ou)
            }) {
                return false;
            }
        }

        // Common Name filter (fuzzy)
        if !self.common_names.is_empty() {
            if !self.common_names.iter().any(|cn| {
                fuzzy_match(&cert.subject, cn) || fuzzy_match(&cert.issuer, cn)
            }) {
                return false;
            }
        }

        // Country filter (fuzzy)
        if !self.countries.is_empty() {
            if !self.countries.iter().any(|c| {
                fuzzy_match(&cert.subject, c) || fuzzy_match(&cert.issuer, c)
            }) {
                return false;
            }
        }

        // Locality filter (fuzzy)
        if !self.localities.is_empty() {
            if !self.localities.iter().any(|l| {
                fuzzy_match(&cert.subject, l) || fuzzy_match(&cert.issuer, l)
            }) {
                return false;
            }
        }

        // State filter (fuzzy)
        if !self.states.is_empty() {
            if !self.states.iter().any(|st| {
                fuzzy_match(&cert.subject, st) || fuzzy_match(&cert.issuer, st)
            }) {
                return false;
            }
        }

        // Serial number filter (fuzzy, case-insensitive)
        if !self.serials.is_empty() {
            if !self.serials.iter().any(|serial| {
                cert.serial_hex.to_lowercase().contains(&serial.to_lowercase())
            }) {
                return false;
            }
        }

        // Subject filter (fuzzy)
        if !self.subjects.is_empty() {
            if !self.subjects.iter().any(|subj| {
                fuzzy_match(&cert.subject, subj)
            }) {
                return false;
            }
        }

        // Issuer filter (fuzzy)
        if !self.issuers.is_empty() {
            if !self.issuers.iter().any(|iss| {
                fuzzy_match(&cert.issuer, iss)
            }) {
                return false;
            }
        }

        // Key algorithm filter (fuzzy with smart matching)
        if !self.key_algorithms.is_empty() {
            if !self.key_algorithms.iter().any(|algo| {
                matches_algorithm(&cert.pubkey_algo, algo)
            }) {
                return false;
            }
        }

        // Signature algorithm filter (fuzzy with smart matching)
        if !self.signature_algorithms.is_empty() {
            if !self.signature_algorithms.iter().any(|algo| {
                matches_algorithm(&cert.signature_algo, algo)
            }) {
                return false;
            }
        }

        // Key size filter
        if !self.key_sizes.is_empty() {
            if let Some(bits) = cert.pubkey_bits {
                if !self.key_sizes.contains(&bits) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Validity period filters
        let now = Utc::now();
        
        if self.expired_only && cert.not_after >= now {
            return false;
        }

        if self.valid_only && (cert.not_before > now || cert.not_after < now) {
            return false;
        }

        // Not before filter
        if let Some(ref filter_date) = self.not_before {
            if cert.not_before < *filter_date {
                return false;
            }
        }

        // Not after filter
        if let Some(ref filter_date) = self.not_after {
            if cert.not_after > *filter_date {
                return false;
            }
        }

        true
    }
}

/// Fuzzy matching: case-insensitive substring search
fn fuzzy_match(text: &str, pattern: &str) -> bool {
    text.to_lowercase().contains(&pattern.to_lowercase())
}

/// Smart algorithm matching with variant support
fn matches_algorithm(algo: &str, pattern: &str) -> bool {
    let algo_lower = algo.to_lowercase();
    let pattern_lower = pattern.to_lowercase();

    // Exact match
    if algo_lower.contains(&pattern_lower) {
        return true;
    }

    // Smart matching for common algorithm families
    match pattern_lower.as_str() {
        // RSA variants
        "rsa" => algo_lower.contains("rsa"),
        "rsa-pss" | "rsapss" | "pss" => algo_lower.contains("pss"),
        "rsa-oaep" | "rsaoaep" | "oaep" => algo_lower.contains("oaep"),
        
        // SHA variants
        "sha" => algo_lower.contains("sha"),
        "sha1" | "sha-1" => algo_lower.contains("sha1") || algo_lower.contains("sha-1"),
        "sha2" => algo_lower.contains("sha2") || algo_lower.contains("sha256") || 
                  algo_lower.contains("sha384") || algo_lower.contains("sha512"),
        "sha224" | "sha-224" => algo_lower.contains("sha224") || algo_lower.contains("sha-224"),
        "sha256" | "sha-256" => algo_lower.contains("sha256") || algo_lower.contains("sha-256"),
        "sha384" | "sha-384" => algo_lower.contains("sha384") || algo_lower.contains("sha-384"),
        "sha512" | "sha-512" => algo_lower.contains("sha512") || algo_lower.contains("sha-512"),
        
        // EC/ECDSA variants
        "ec" | "ecc" => algo_lower.contains("ec") || algo_lower.contains("ecdsa"),
        "ecdsa" => algo_lower.contains("ecdsa"),
        "ed25519" => algo_lower.contains("ed25519"),
        "ed448" => algo_lower.contains("ed448"),
        "eddsa" => algo_lower.contains("ed25519") || algo_lower.contains("ed448"),
        
        // DSA
        "dsa" => algo_lower.contains("dsa"),
        
        // MD5
        "md5" => algo_lower.contains("md5"),
        
        // Post-quantum
        "dilithium" | "ml-dsa" | "mldsa" => algo_lower.contains("dilithium") || algo_lower.contains("ml-dsa"),
        "kyber" | "ml-kem" | "mlkem" => algo_lower.contains("kyber") || algo_lower.contains("ml-kem"),
        
        // Chinese standards
        "sm2" => algo_lower.contains("sm2"),
        "sm3" => algo_lower.contains("sm3"),
        
        // Russian standards
        "gost" => algo_lower.contains("gost"),
        
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzy_match() {
        assert!(fuzzy_match("CN=Apple Inc.", "apple"));
        assert!(fuzzy_match("CN=Apple Inc.", "APPLE"));
        assert!(fuzzy_match("O=Microsoft Corporation", "microsoft"));
        assert!(!fuzzy_match("CN=Google", "apple"));
    }

    #[test]
    fn test_algorithm_matching() {
        assert!(matches_algorithm("sha256WithRSAEncryption", "rsa"));
        assert!(matches_algorithm("sha256WithRSAEncryption", "sha256"));
        assert!(matches_algorithm("sha256WithRSAEncryption", "sha"));
        assert!(matches_algorithm("ecdsa-with-SHA256", "ecdsa"));
        assert!(matches_algorithm("ecdsa-with-SHA256", "ec"));
        assert!(matches_algorithm("Ed25519", "ed25519"));
        assert!(matches_algorithm("Ed25519", "eddsa"));
        assert!(!matches_algorithm("sha256WithRSAEncryption", "dsa"));
    }
}
