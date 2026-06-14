use rusqlite::{Connection, Result, params};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ThreatRecord {
    pub id: i64,
    pub hash: String,
    pub threat_name: String,
    pub severity: i32,
    pub first_seen: String,
    pub last_seen: String,
    pub file_path: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct ThreatMatch {
    pub threat_name: String,
    pub severity: i32,
}

/// Looks up a SHA-256 hash in the threat database.
/// Returns Some(threat_name, severity) if found, None if clean.
pub fn check_against_db(conn: &Connection, hash: &str) -> Result<Option<ThreatMatch>> {
    let mut stmt = conn.prepare_cached(
        "SELECT threat_name, severity FROM threats WHERE hash = ?1 AND status = 'active'",
    )?;

    let mut rows = stmt.query(params![hash.to_ascii_lowercase()])?;
    match rows.next()? {
        Some(row) => Ok(Some(ThreatMatch {
            threat_name: row.get(0)?,
            severity: row.get(1)?,
        })),
        None => Ok(None),
    }
}

/// Records a detected threat in the database.
pub fn record_threat(
    conn: &Connection,
    hash: &str,
    threat_name: &str,
    severity: i32,
    file_path: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO threats (hash, threat_name, severity, file_path, status)
         VALUES (?1, ?2, ?3, ?4, 'active')
         ON CONFLICT(hash) DO UPDATE SET
            last_seen = datetime('now'),
            file_path = COALESCE(?4, file_path)",
        params![hash.to_ascii_lowercase(), threat_name, severity, file_path],
    )?;
    Ok(())
}

/// Returns the total count of active threats in the database.
pub fn threat_count(conn: &Connection) -> Result<u64> {
    conn.query_row(
        "SELECT COUNT(*) FROM threats WHERE status = 'active'",
        [],
        |row| row.get::<_, u64>(0),
    )
}
