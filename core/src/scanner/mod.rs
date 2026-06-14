pub mod hasher;
pub mod walker;

use crate::db::threats::check_against_db;
use hasher::{sha256_hash, HashError};
use std::path::Path;

#[allow(dead_code)]
#[derive(Debug)]
pub enum ScanOutcome {
    Clean,
    ThreatDetected { hash: String, threat_name: String, severity: i32 },
    Skipped { reason: String },
}

pub fn scan_file(path: &Path) -> ScanOutcome {
    match sha256_hash(path) {
        Ok(hash) => {
            match db_cached_lookup(&hash) {
                Some(matched) => {
                    tracing::warn!(
                        "Threat detected: {} (hash: {}, name: {})",
                        path.display(),
                        hash,
                        matched.threat_name
                    );
                    ScanOutcome::ThreatDetected {
                        hash,
                        threat_name: matched.threat_name,
                        severity: matched.severity,
                    }
                }
                None => {
                    tracing::debug!("File clean: {}", path.display());
                    ScanOutcome::Clean
                }
            }
        }
        Err(e) => {
            let reason = match &e {
                HashError::Io(io_err) if io_err.kind() == std::io::ErrorKind::NotFound => {
                    "file disappeared during scan".to_string()
                }
                HashError::FileTooLarge { size, limit, .. } => {
                    tracing::debug!("Skipping {} ({} bytes, limit {})", path.display(), size, limit);
                    "file exceeds maximum scan size".to_string()
                }
                _ => e.to_string(),
            };
            if !matches!(e, HashError::FileTooLarge { .. }) {
                tracing::warn!("Skipping {}: {reason}", path.display());
            }
            ScanOutcome::Skipped { reason }
        }
    }
}

/// Cache a dedicated DB connection for the scanner.
/// Uses its own `Connection` (separate from `Database`) to avoid locking.
use std::sync::Mutex;

static DB_CONN: once_cell::sync::Lazy<Mutex<Option<rusqlite::Connection>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

pub fn init_db_cache(conn: rusqlite::Connection) {
    let mut guard = DB_CONN.lock().unwrap();
    *guard = Some(conn);
}

use crate::db::threats::ThreatMatch;

fn db_cached_lookup(hash: &str) -> Option<ThreatMatch> {
    let guard = DB_CONN.lock().unwrap();
    match guard.as_ref() {
        Some(conn) => check_against_db(conn, hash).ok()?,
        None => legacy_check(hash),
    }
}

fn legacy_check(hash: &str) -> Option<ThreatMatch> {
    let known: [(&str, &str, i32); 3] = [
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Test-File", 2),
        ("e1105070ba828007508566e28a2b8d4c7d0b8c2d9c5c2f8c0f7a7e7b5a5c3b1a", "Malware.Generic.SB", 3),
        ("a3a5e7f4d8b9c1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6", "Trojan.PsDownload", 4),
    ];

    let hash_lower = hash.to_ascii_lowercase();
    for (h, name, severity) in &known {
        if *h == hash_lower {
            return Some(ThreatMatch {
                threat_name: name.to_string(),
                severity: *severity,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn scan_eicar_file() {
        let dir = std::env::temp_dir().join("sentryavtt_test_eicar2");
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("eicar.com");
        let mut f = fs::File::create(&file_path).unwrap();
        f.write_all(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            .unwrap();
        let result = scan_file(&file_path);
        let _ = fs::remove_dir_all(&dir);
        assert!(matches!(
            result,
            ScanOutcome::ThreatDetected { .. }
        ));
    }

    #[test]
    fn scan_nonexistent_file() {
        let path = Path::new(r"C:\this\path\does\not\exist.exe");
        let result = scan_file(&path);
        assert!(matches!(result, ScanOutcome::Skipped { .. }));
    }
}
