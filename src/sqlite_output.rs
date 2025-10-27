use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::path::Path;

use crate::dirscan::CertWithDuplicateInfo;
use crate::parser::ParsedCert;

/// Initialize SQLite database with schema
pub fn init_database(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open SQLite database: {}", db_path.display()))?;

    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        
        CREATE TABLE IF NOT EXISTS certificate (
            sha256 TEXT PRIMARY KEY,
            subject TEXT,
            issuer TEXT,
            serial TEXT,
            not_before TEXT,
            not_after TEXT,
            public_key_algorithm TEXT,
            public_key_bits INTEGER,
            signature_algorithm TEXT,
            first_seen_path TEXT NOT NULL,
            first_seen_offset INTEGER NOT NULL,
            first_seen_size INTEGER NOT NULL,
            first_seen_global_index INTEGER NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1
        );
        
        CREATE TABLE IF NOT EXISTS occurrence (
            sha256 TEXT NOT NULL,
            path TEXT NOT NULL,
            offset INTEGER NOT NULL,
            size INTEGER NOT NULL,
            global_index INTEGER NOT NULL,
            source TEXT NOT NULL,
            PRIMARY KEY (sha256, path, offset),
            FOREIGN KEY (sha256) REFERENCES certificate(sha256) ON DELETE CASCADE
        );
        
        CREATE INDEX IF NOT EXISTS idx_occurrence_sha256 ON occurrence(sha256);
        CREATE INDEX IF NOT EXISTS idx_occurrence_path ON occurrence(path);
        CREATE INDEX IF NOT EXISTS idx_certificate_subject ON certificate(subject);
        CREATE INDEX IF NOT EXISTS idx_certificate_issuer ON certificate(issuer);
        "#,
    )?;

    Ok(conn)
}

/// SQLite writer for batch operations
pub struct SqliteWriter {
    conn: Connection,
    insert_cert_stmt: String,
    insert_occurrence_stmt: String,
    update_count_stmt: String,
}

impl SqliteWriter {
    pub fn new(db_path: &Path) -> Result<Self> {
        let conn = init_database(db_path)?;

        Ok(Self {
            conn,
            insert_cert_stmt: r#"
                INSERT OR IGNORE INTO certificate (
                    sha256, subject, issuer, serial, not_before, not_after,
                    public_key_algorithm, public_key_bits, signature_algorithm,
                    first_seen_path, first_seen_offset, first_seen_size,
                    first_seen_global_index, occurrence_count
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1)
            "#.to_string(),
            insert_occurrence_stmt: r#"
                INSERT OR IGNORE INTO occurrence (
                    sha256, path, offset, size, global_index, source
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#.to_string(),
            update_count_stmt: r#"
                UPDATE certificate 
                SET occurrence_count = (
                    SELECT COUNT(*) FROM occurrence WHERE sha256 = ?1
                )
                WHERE sha256 = ?1
            "#.to_string(),
        })
    }

    /// Begin a transaction for batch writes
    pub fn begin_transaction(&mut self) -> Result<()> {
        self.conn.execute("BEGIN TRANSACTION", [])?;
        Ok(())
    }

    /// Commit the current transaction
    pub fn commit(&mut self) -> Result<()> {
        self.conn.execute("COMMIT", [])?;
        Ok(())
    }

    /// Write a certificate and its occurrence
    pub fn write_certificate(
        &self,
        cert_info: &CertWithDuplicateInfo,
        parsed: Option<&ParsedCert>,
    ) -> Result<()> {
        let sha256 = cert_info.cert.sha256_hex();
        let source = match &cert_info.cert.source {
            crate::scanner::CertSource::DerCandidate { .. } => "DER",
            crate::scanner::CertSource::PemBlock { .. } => "PEM",
        };

        // Insert certificate metadata (only on first occurrence)
        if !cert_info.is_duplicate {
            self.conn.execute(
                &self.insert_cert_stmt,
                params![
                    sha256,
                    parsed.map(|p| &p.subject),
                    parsed.map(|p| &p.issuer),
                    parsed.map(|p| &p.serial_hex),
                    parsed.map(|p| p.not_before.to_rfc3339()),
                    parsed.map(|p| p.not_after.to_rfc3339()),
                    parsed.map(|p| &p.pubkey_algo),
                    parsed.and_then(|p| p.pubkey_bits),
                    parsed.map(|p| &p.signature_algo),
                    cert_info.path.display().to_string(),
                    cert_info.cert.offset as i64,
                    cert_info.cert.raw_range_len as i64,
                    cert_info.global_index as i64,
                ],
            )?;
        }

        // Always insert occurrence
        self.conn.execute(
            &self.insert_occurrence_stmt,
            params![
                sha256,
                cert_info.path.display().to_string(),
                cert_info.cert.offset as i64,
                cert_info.cert.raw_range_len as i64,
                cert_info.global_index as i64,
                source,
            ],
        )?;

        // Update occurrence count
        self.conn.execute(&self.update_count_stmt, params![sha256])?;

        Ok(())
    }

    /// Get statistics about the database
    pub fn get_stats(&self) -> Result<(usize, usize)> {
        let unique: usize = self.conn.query_row(
            "SELECT COUNT(*) FROM certificate",
            [],
            |row| row.get(0),
        )?;

        let total: usize = self.conn.query_row(
            "SELECT COUNT(*) FROM occurrence",
            [],
            |row| row.get(0),
        )?;

        Ok((unique, total))
    }
}
