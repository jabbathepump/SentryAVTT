use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection};
use uuid::Uuid;

const QUARANTINE_DIR: &str = r"C:\ProgramData\SentryAVTT\Quarantine";

#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub quarantined_path: String,
    pub quarantined_at: String,
    pub hash: String,
    pub threat_name: String,
    pub severity: i32,
    pub status: String,
}

/// Moves a file into quarantine with a deny-ACE ACL on the copied/renamed file.
/// Returns the quarantine entry on success.
pub fn quarantine_file(
    conn: &Mutex<Connection>,
    source: &Path,
    hash: &str,
    threat_name: &str,
    severity: i32,
) -> Result<QuarantineEntry, String> {
    let quarantine_dir = PathBuf::from(QUARANTINE_DIR);
    std::fs::create_dir_all(&quarantine_dir).map_err(|e| format!("create quarantine dir: {e}"))?;

    let id = Uuid::new_v4().to_string();
    let ext = source
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    let dest_name = format!("{id}.{ext}.quarantine");
    let dest_path = quarantine_dir.join(&dest_name);

    // Copy then delete original (safer than direct move)
    if let Err(e) = std::fs::copy(source, &dest_path) {
        return Err(format!("copy to quarantine: {e}"));
    }

    // Apply deny-ACE via icacls to prevent execution
    if let Err(e) = apply_deny_acl(&dest_path) {
        // Non-fatal: log warning but proceed
        tracing::warn!("Failed to set deny ACL on quarantined file: {e}");
    }

    // Remove original
    if let Err(e) = std::fs::remove_file(source) {
        // Restore quarantined copy if we can't remove the original
        let _ = std::fs::remove_file(&dest_path);
        return Err(format!("remove original file: {e}"));
    }

    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
    conn.execute(
        "INSERT INTO quarantine (id, original_path, quarantined_path, hash, threat_name, severity, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'quarantined')",
        params![
            id,
            source.display().to_string(),
            dest_path.display().to_string(),
            hash,
            threat_name,
            severity
        ],
    )
    .map_err(|e| format!("db insert: {e}"))?;

    Ok(QuarantineEntry {
        id,
        original_path: source.display().to_string(),
        quarantined_path: dest_path.display().to_string(),
        quarantined_at: now,
        hash: hash.to_string(),
        threat_name: threat_name.to_string(),
        severity,
        status: "quarantined".to_string(),
    })
}

/// Restores a quarantined file back to its original path.
pub fn restore_file(conn: &Mutex<Connection>, id: &str) -> Result<(), String> {
    let (original_path, quarantined_path) = {
        let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let mut stmt = conn
            .prepare("SELECT original_path, quarantined_path FROM quarantine WHERE id = ?1 AND status = 'quarantined'")
            .map_err(|e| format!("db prepare: {e}"))?;
        stmt.query_row(params![id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| format!("db query: {e}"))?
    };

    let src = PathBuf::from(&quarantined_path);
    let dst = PathBuf::from(&original_path);

    if !src.exists() {
        return Err("quarantined file not found on disk".to_string());
    }

    // Ensure parent directory exists
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create parent dir: {e}"))?;
    }

    std::fs::rename(&src, &dst).map_err(|e| format!("restore file: {e}"))?;

    let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
    conn.execute(
        "UPDATE quarantine SET status = 'restored' WHERE id = ?1",
        params![id],
    )
    .map_err(|e| format!("db update: {e}"))?;

    Ok(())
}

/// Permanently deletes a quarantined file from disk and marks it as deleted in DB.
pub fn delete_file(conn: &Mutex<Connection>, id: &str) -> Result<(), String> {
    let quarantined_path = {
        let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let mut stmt = conn
            .prepare("SELECT quarantined_path FROM quarantine WHERE id = ?1 AND status = 'quarantined'")
            .map_err(|e| format!("db prepare: {e}"))?;
        stmt.query_row(params![id], |row| row.get::<_, String>(0))
            .map_err(|e| format!("db query: {e}"))?
    };

    let path = PathBuf::from(&quarantined_path);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("delete file: {e}"))?;
    }

    let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
    conn.execute(
        "UPDATE quarantine SET status = 'deleted' WHERE id = ?1",
        params![id],
    )
    .map_err(|e| format!("db update: {e}"))?;

    Ok(())
}

/// Lists all quarantine entries from the database.
pub fn list_quarantine(conn: &Mutex<Connection>) -> Result<Vec<QuarantineEntry>, String> {
    let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
    let mut stmt = conn
        .prepare(
            "SELECT id, original_path, quarantined_path, quarantined_at, hash, threat_name, severity, status
             FROM quarantine ORDER BY quarantined_at DESC",
        )
        .map_err(|e| format!("db prepare: {e}"))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(QuarantineEntry {
                id: row.get(0)?,
                original_path: row.get(1)?,
                quarantined_path: row.get(2)?,
                quarantined_at: row.get(3)?,
                hash: row.get(4)?,
                threat_name: row.get(5)?,
                severity: row.get(6)?,
                status: row.get(7)?,
            })
        })
        .map_err(|e| format!("db query: {e}"))?;

    rows.collect::<Result<Vec<_>, _>>().map_err(|e| format!("db collect: {e}"))
}

/// Returns the count of currently quarantined items.
pub fn quarantine_count(conn: &Mutex<Connection>) -> Result<u64, String> {
    let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
    conn.query_row(
        "SELECT COUNT(*) FROM quarantine WHERE status = 'quarantined'",
        [],
        |row| row.get::<_, u64>(0),
    )
    .map_err(|e| format!("db query: {e}"))
}

fn apply_deny_acl(path: &Path) -> Result<(), String> {
    let path_str = path.display().to_string();

    // Use icacls to deny Everyone full access to the quarantined file
    let output = std::process::Command::new("icacls")
        .args([
            &path_str,
            "/deny",
            "Everyone:(R,W,D,DC,WA,X)",
            "/inheritance:r",
        ])
        .output()
        .map_err(|e| format!("icacls spawn: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("icacls failed: {stderr}"));
    }

    Ok(())
}
