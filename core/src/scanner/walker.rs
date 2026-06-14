use std::path::Path;

use crate::db::Database;
use crate::scanner::{scan_file, ScanOutcome};

/// Walks a directory tree and scans every file.
/// Calls `on_progress` periodically so the caller can stream events over IPC.
/// Calls `on_threat` for each threat detected with its metadata.
/// Returns total files scanned and threats found.
pub fn walk_and_scan<F, G>(
    root: &Path,
    db: &Database,
    mut on_progress: F,
    mut on_threat: G,
) -> (u64, u64)
where
    F: FnMut(u64, u64, u64, &str),
    G: FnMut(&str, &str, i32, &Path),
{
    let mut files_scanned = 0u64;
    let mut threats_found = 0u64;
    let batch_size = 25u64;

    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .same_file_system(true)
        .into_iter()
        .filter_entry(|e| !is_skip_dir(e))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        if is_skip_file(path) {
            continue;
        }

        let outcome = scan_file(path);
        match &outcome {
            ScanOutcome::ThreatDetected { hash, threat_name, severity } => {
                threats_found += 1;

                // Record in database
                if let Ok(conn) = db.conn.lock() {
                    let _ = crate::db::threats::record_threat(
                        &conn, hash, threat_name, *severity, path.to_str(),
                    );
                }

                // Quarantine the file
                if let Err(e) = crate::quarantine::quarantine_file(
                    &db.conn, path, hash, threat_name, *severity,
                ) {
                    tracing::warn!("Failed to quarantine {}: {e}", path.display());
                }

                // Notify caller
                on_threat(hash, threat_name, *severity, path);
            }
            ScanOutcome::Clean => {
                files_scanned += 1;
            }
            ScanOutcome::Skipped { .. } => {}
        }

        // Call progress callback at batch intervals
        if (files_scanned + threats_found) % batch_size == 0 {
            let current = path.display().to_string();
            on_progress(files_scanned, threats_found, 0, &current);
        }
    }

    // Final progress report
    on_progress(files_scanned, threats_found, 0, "");

    (files_scanned, threats_found)
}

fn is_skip_dir(entry: &walkdir::DirEntry) -> bool {
    let name = entry
        .file_name()
        .to_str()
        .unwrap_or("");

    // Skip common system/junction directories
    name == "System Volume Information"
        || name == "$RECYCLE.BIN"
        || name == "Recovery"
        || name == "Windows.old"
        || name.starts_with("$")
}

fn is_skip_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if name.starts_with('.') || name.ends_with(".tmp") || name.ends_with(".bak") || name == "swapfile.sys" || name == "pagefile.sys" {
        return true;
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let skip = ["log", "dmp", "cache", "idx", "lock", "sys"];
        if skip.contains(&ext.to_ascii_lowercase().as_str()) {
            return true;
        }
    }

    false
}
