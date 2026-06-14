use rusqlite::{params, Connection};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ThreatEntry {
    hash: String,
    threat_name: String,
    severity: i32,
}

fn insert_threats(conn: &Connection, entries: &[ThreatEntry]) -> Result<usize, String> {
    if entries.is_empty() {
        return Ok(0);
    }

    let mut stmt = conn
        .prepare_cached(
            "INSERT OR IGNORE INTO threats (hash, threat_name, severity, status)
             VALUES (?1, ?2, ?3, 'active')",
        )
        .map_err(|e| format!("DB prepare: {e}"))?;

    let mut count = 0usize;
    for entry in entries {
        if stmt
            .execute(params![entry.hash.to_ascii_lowercase(), entry.threat_name, entry.severity])
            .is_ok()
        {
            count += 1;
        }
    }
    Ok(count)
}

/// Updates the threat DB from a JSON feed.
/// Format: `[{"hash": "...", "threat_name": "...", "severity": N}, ...]`
pub fn update_from_json(conn: &Connection, url: &str) -> Result<usize, String> {
    tracing::info!("Fetching threat definitions from {url}");

    let body = fetch_url(url)?;

    let entries: Vec<ThreatEntry> =
        serde_json::from_str(&body).map_err(|e| format!("JSON parse error: {e}"))?;

    let count = insert_threats(conn, &entries)?;
    tracing::info!("Threat database updated: {count} new signatures added from JSON");
    Ok(count)
}

/// Updates the threat DB from a MalwareBazaar CSV feed.
/// Format: CSV with columns: first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,
/// file_name,file_type_guess,mime_type,signature,clamav,vtpercent,imphash,ssdeep,tlshat
/// Comment lines start with `#`.
pub fn update_from_csv(conn: &Connection, url: &str) -> Result<usize, String> {
    tracing::info!("Fetching MalwareBazaar CSV from {url}");

    let body = fetch_url(url)?;

    let mut entries: Vec<ThreatEntry> = Vec::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols = split_csv_line(line);
        if cols.len() < 9 {
            continue;
        }
        let hash = cols[1].trim();
        if hash.len() != 64 {
            continue;
        }
        let signature = cols[8].trim();
        let file_name = cols[5].trim();
        let threat_name = if signature.is_empty() || signature == "unknown" {
            if file_name.is_empty() {
                "generic-threat"
            } else {
                file_name
            }
        } else {
            signature
        };
        entries.push(ThreatEntry {
            hash: hash.to_string(),
            threat_name: threat_name.to_string(),
            severity: 1,
        });
    }

    let count = insert_threats(conn, &entries)?;
    tracing::info!("Threat database updated: {count} new signatures added from CSV");
    Ok(count)
}

fn fetch_url(url: &str) -> Result<String, String> {
    let mut response = ureq::get(url)
        .call()
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    response
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("Failed to read response body: {e}"))
}

/// Splits a CSV line into columns, handling double-quoted fields.
fn split_csv_line(line: &str) -> Vec<&str> {
    let mut cols: Vec<&str> = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'"' {
            in_quotes = !in_quotes;
        } else if bytes[i] == b',' && !in_quotes {
            cols.push(&line[start..i]);
            start = i + 1;
        }
    }
    cols.push(&line[start..]);
    // Strip surrounding quotes from each field
    for col in cols.iter_mut() {
        let trimmed = col.trim();
        if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
            *col = &trimmed[1..trimmed.len() - 1];
        }
    }
    cols
}

/// Backward-compat alias.
pub fn update_from_url(conn: &Connection, url: &str) -> Result<usize, String> {
    update_from_json(conn, url)
}
