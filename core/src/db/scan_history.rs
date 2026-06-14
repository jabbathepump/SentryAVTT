use rusqlite::{Connection, Result, params};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ScanRecord {
    pub scan_id: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub files_scanned: u64,
    pub threats_found: u64,
    pub target_path: String,
    pub status: String,
}

/// Creates a new scan history entry and returns the scan_id.
pub fn start_scan(conn: &Connection, scan_id: &str, target_path: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO scan_history (scan_id, target_path, status)
         VALUES (?1, ?2, 'running')",
        params![scan_id, target_path],
    )?;
    Ok(())
}

/// Marks a scan as completed with final counts.
pub fn complete_scan(
    conn: &Connection,
    scan_id: &str,
    files_scanned: u64,
    threats_found: u64,
    status: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE scan_history
         SET completed_at = datetime('now'),
             files_scanned = ?2,
             threats_found = ?3,
             status = ?4
         WHERE scan_id = ?1",
        params![scan_id, files_scanned, threats_found, status],
    )?;
    Ok(())
}

#[allow(dead_code)]
pub fn recent_scans(conn: &Connection, limit: u32) -> Result<Vec<ScanRecord>> {
    let mut stmt = conn.prepare_cached(
        "SELECT scan_id, started_at, completed_at, files_scanned,
                threats_found, target_path, status
         FROM scan_history
         ORDER BY started_at DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map(params![limit], |row| {
        Ok(ScanRecord {
            scan_id: row.get(0)?,
            started_at: row.get(1)?,
            completed_at: row.get(2)?,
            files_scanned: row.get(3)?,
            threats_found: row.get(4)?,
            target_path: row.get(5)?,
            status: row.get(6)?,
        })
    })?;

    rows.collect()
}
