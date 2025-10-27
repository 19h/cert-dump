use anyhow::{Context, Result};
use crossbeam_channel::{bounded, Sender, Receiver};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::thread;
use walkdir::WalkDir;

use crate::scanner::{scan_certificates, FoundCert};

/// Configuration for directory scanning
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub recursive: bool,
    pub follow_symlinks: bool,
    pub max_depth: Option<usize>,
    pub extensions: Option<Vec<String>>,
    pub threads: usize,
    pub max_file_size: u64,
    pub unique_only: bool,
    pub mark_duplicates: bool,
    pub verbose: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            recursive: false,
            follow_symlinks: false,
            max_depth: None,
            extensions: None,
            threads: num_cpus::get().max(1),
            max_file_size: 512 * 1024 * 1024, // 512 MB
            unique_only: false,
            mark_duplicates: false,
            verbose: false,
        }
    }
}

/// A file job to be processed
#[derive(Debug, Clone)]
pub struct FileJob {
    pub path: PathBuf,
    pub size: u64,
}

/// Result from scanning a single file
#[derive(Debug)]
pub struct ScanResult {
    pub path: PathBuf,
    pub file_size: u64,
    pub certs: Vec<FoundCert>,
}

/// Information about the first occurrence of a certificate
#[derive(Debug, Clone, Serialize)]
pub struct FirstSeen {
    pub global_index: u64,
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub offset: usize,
    pub size: usize,
    pub count: u64,
}

/// Serialize PathBuf as string for JSON
fn serialize_path<S>(path: &PathBuf, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&path.display().to_string())
}

/// Certificate with duplicate tracking information
#[derive(Debug, Clone)]
pub struct CertWithDuplicateInfo {
    pub cert: FoundCert,
    pub path: PathBuf,
    pub global_index: u64,
    pub is_duplicate: bool,
    pub duplicate_of: Option<FirstSeen>,
}

/// Tracks duplicate certificates across files
pub struct DuplicateTracker {
    seen: HashMap<[u8; 32], FirstSeen>,
    global_index: u64,
}

impl DuplicateTracker {
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            global_index: 0,
        }
    }

    /// Process a certificate and return tracking information
    pub fn process(&mut self, cert: FoundCert, path: PathBuf) -> CertWithDuplicateInfo {
        let digest = cert.sha256_digest();
        
        if let Some(first_seen) = self.seen.get_mut(&digest) {
            // This is a duplicate
            first_seen.count += 1;
            CertWithDuplicateInfo {
                cert,
                path,
                global_index: self.global_index,
                is_duplicate: true,
                duplicate_of: Some(first_seen.clone()),
            }
        } else {
            // First occurrence
            let global_index = self.global_index;
            let first_seen = FirstSeen {
                global_index,
                path: path.clone(),
                offset: cert.offset,
                size: cert.raw_range_len,
                count: 1,
            };
            self.seen.insert(digest, first_seen);
            
            CertWithDuplicateInfo {
                cert,
                path,
                global_index,
                is_duplicate: false,
                duplicate_of: None,
            }
        }
    }

    /// Increment global index (call after processing each certificate)
    pub fn increment_index(&mut self) {
        self.global_index += 1;
    }
}

/// Enumerate files to scan based on input paths and config
pub fn enumerate_files(
    paths: Vec<PathBuf>,
    config: &ScanConfig,
) -> Result<Vec<FileJob>> {
    let mut jobs = Vec::new();
    let mut seen_inodes = HashSet::new();

    for path in paths {
        if path.is_file() {
            // Single file
            let metadata = fs::metadata(&path)
                .with_context(|| format!("Failed to read metadata for {:?}", path))?;
            
            jobs.push(FileJob {
                path,
                size: metadata.len(),
            });
        } else if path.is_dir() {
            if !config.recursive {
                anyhow::bail!(
                    "Input path {:?} is a directory. Use -R/--recursive to scan directories.",
                    path
                );
            }

            // Recursive directory scan
            let walker = WalkDir::new(&path)
                .follow_links(config.follow_symlinks)
                .max_depth(config.max_depth.unwrap_or(usize::MAX));

            for entry in walker {
                match entry {
                    Ok(entry) => {
                        if !entry.file_type().is_file() {
                            continue;
                        }

                        let entry_path = entry.path();
                        
                        // Apply extension filter if specified
                        if let Some(ref exts) = config.extensions {
                            if let Some(ext) = entry_path.extension() {
                                let ext_str = ext.to_string_lossy().to_lowercase();
                                if !exts.iter().any(|e| e.to_lowercase() == ext_str) {
                                    if config.verbose {
                                        eprintln!("Skipping {:?}: extension not in filter", entry_path);
                                    }
                                    continue;
                                }
                            } else {
                                // No extension, skip if filter is set
                                if config.verbose {
                                    eprintln!("Skipping {:?}: no extension", entry_path);
                                }
                                continue;
                            }
                        }

                        if let Ok(metadata) = entry.metadata() {
                            // Check for hard link duplicates (Unix-specific)
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::MetadataExt;
                                let inode_id = (metadata.dev(), metadata.ino());
                                if !seen_inodes.insert(inode_id) {
                                    if config.verbose {
                                        eprintln!("Skipping {:?}: hard link duplicate", entry_path);
                                    }
                                    continue;
                                }
                            }

                            let file_size = metadata.len();
                            
                            // Check size limit
                            if file_size > config.max_file_size {
                                if config.verbose {
                                    eprintln!(
                                        "Skipping {:?}: size {} exceeds limit {}",
                                        entry_path, file_size, config.max_file_size
                                    );
                                }
                                continue;
                            }

                            jobs.push(FileJob {
                                path: entry_path.to_path_buf(),
                                size: file_size,
                            });
                        }
                    }
                    Err(e) => {
                        if config.verbose {
                            eprintln!("Warning: Failed to read directory entry: {}", e);
                        }
                    }
                }
            }
        } else {
            anyhow::bail!("Input path {:?} is neither a file nor a directory", path);
        }
    }

    Ok(jobs)
}

/// Scan files in parallel and process results with duplicate tracking
pub fn scan_files_parallel(
    jobs: Vec<FileJob>,
    config: &ScanConfig,
    mut result_handler: impl FnMut(CertWithDuplicateInfo) -> Result<()>,
) -> Result<()> {
    let (work_tx, work_rx): (Sender<FileJob>, Receiver<FileJob>) = bounded(config.threads * 2);
    let (result_tx, result_rx): (Sender<Result<ScanResult>>, Receiver<Result<ScanResult>>) =
        bounded(config.threads * 2);

    // Spawn worker threads
    let mut workers = Vec::new();
    for worker_id in 0..config.threads {
        let work_rx = work_rx.clone();
        let result_tx = result_tx.clone();
        let verbose = config.verbose;

        let worker = thread::spawn(move || {
            if verbose {
                eprintln!("Worker {} started", worker_id);
            }

            while let Ok(job) = work_rx.recv() {
                let result = scan_file_worker(&job, verbose);
                if result_tx.send(result).is_err() {
                    break;
                }
            }

            if verbose {
                eprintln!("Worker {} finished", worker_id);
            }
        });

        workers.push(worker);
    }

    // Drop original senders so receivers know when all work is done
    drop(work_rx);
    drop(result_tx);

    // Producer thread to enqueue jobs
    let producer = {
        let work_tx = work_tx.clone();
        let verbose = config.verbose;
        thread::spawn(move || {
            if verbose {
                eprintln!("Enqueuing {} files for scanning", jobs.len());
            }
            for job in jobs {
                if work_tx.send(job).is_err() {
                    break;
                }
            }
            if verbose {
                eprintln!("All files enqueued");
            }
        })
    };

    drop(work_tx);

    // Aggregator: receive results and track duplicates
    let mut tracker = DuplicateTracker::new();
    let mut file_count = 0;
    let mut total_certs = 0;

    for result in result_rx {
        match result {
            Ok(scan_result) => {
                file_count += 1;
                let file_cert_count = scan_result.certs.len();
                total_certs += file_cert_count;

                if config.verbose {
                    eprintln!(
                        "Processed {}: {} certificate(s)",
                        scan_result.path.display(),
                        file_cert_count
                    );
                }

                for cert in scan_result.certs {
                    let cert_info = tracker.process(cert, scan_result.path.clone());
                    
                    // Skip duplicates if unique_only is set
                    if config.unique_only && cert_info.is_duplicate {
                        if config.verbose {
                            if let Some(ref first) = cert_info.duplicate_of {
                                eprintln!(
                                    "Skipping duplicate: SHA-256 {} (first seen in {} at offset 0x{:X})",
                                    cert_info.cert.sha256_hex(),
                                    first.path.display(),
                                    first.offset
                                );
                            }
                        }
                    } else {
                        result_handler(cert_info)?;
                    }
                    
                    tracker.increment_index();
                }
            }
            Err(e) => {
                if config.verbose {
                    eprintln!("Error scanning file: {}", e);
                }
            }
        }
    }

    // Wait for all threads to finish
    producer.join().ok();
    for worker in workers {
        worker.join().ok();
    }

    if config.verbose {
        eprintln!(
            "Scan complete: {} files processed, {} total certificates found",
            file_count, total_certs
        );
    }

    Ok(())
}

/// Worker function to scan a single file
fn scan_file_worker(job: &FileJob, verbose: bool) -> Result<ScanResult> {
    let data = fs::read(&job.path)
        .with_context(|| format!("Failed to read file {:?}", job.path))?;

    if verbose {
        eprintln!("Scanning {} ({} bytes)", job.path.display(), data.len());
    }

    let certs = scan_certificates(&data, verbose)?;

    Ok(ScanResult {
        path: job.path.clone(),
        file_size: job.size,
        certs,
    })
}
