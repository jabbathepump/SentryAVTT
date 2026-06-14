use rusqlite::{Connection, Result};

pub fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS threats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            hash        TEXT    NOT NULL UNIQUE,
            threat_name TEXT    NOT NULL DEFAULT 'unknown',
            severity    INTEGER NOT NULL DEFAULT 3,
            first_seen  TEXT    NOT NULL DEFAULT (datetime('now')),
            last_seen   TEXT    NOT NULL DEFAULT (datetime('now')),
            file_path   TEXT,
            status      TEXT    NOT NULL DEFAULT 'active'
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        TEXT    NOT NULL UNIQUE,
            started_at     TEXT    NOT NULL DEFAULT (datetime('now')),
            completed_at   TEXT,
            files_scanned  INTEGER NOT NULL DEFAULT 0,
            threats_found  INTEGER NOT NULL DEFAULT 0,
            target_path    TEXT,
            status         TEXT    NOT NULL DEFAULT 'running'
        );

        CREATE TABLE IF NOT EXISTS config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_threats_hash ON threats(hash);
        CREATE INDEX IF NOT EXISTS idx_scan_history_started ON scan_history(started_at DESC);

        CREATE TABLE IF NOT EXISTS quarantine (
            id               TEXT    PRIMARY KEY,
            original_path    TEXT    NOT NULL,
            quarantined_path TEXT    NOT NULL,
            quarantined_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            hash             TEXT    NOT NULL DEFAULT '',
            threat_name      TEXT    NOT NULL DEFAULT 'unknown',
            severity         INTEGER NOT NULL DEFAULT 3,
            status           TEXT    NOT NULL DEFAULT 'quarantined'
        );

        CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
        ",
    )?;

    Ok(())
}

pub fn seed_known_threats(conn: &Connection) -> Result<()> {
    let known: [(&str, &str, i32); 3] = [
        (
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "EICAR-Test-File",
            2,
        ),
        (
            "e1105070ba828007508566e28a2b8d4c7d0b8c2d9c5c2f8c0f7a7e7b5a5c3b1a",
            "Malware.Generic.SB",
            3,
        ),
        (
            "a3a5e7f4d8b9c1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
            "Trojan.PsDownload",
            4,
        ),
    ];

    let mut stmt = conn.prepare_cached(
        "INSERT OR IGNORE INTO threats (hash, threat_name, severity, status)
         VALUES (?1, ?2, ?3, 'active')",
    )?;

    for (hash, name, severity) in &known {
        stmt.execute(rusqlite::params![hash, name, severity])?;
    }

    Ok(())
}
