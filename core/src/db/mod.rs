pub mod schema;
pub mod scan_history;
pub mod threats;
pub mod updater;

use rusqlite::Connection;
use std::sync::Mutex;

/// Opens a fresh SQLite connection, runs pragmas and schema init.
pub fn open_database() -> Result<Connection, Box<dyn std::error::Error>> {
    let db_dir = std::path::PathBuf::from(r"C:\ProgramData\SentryAVTT\Data");
    std::fs::create_dir_all(&db_dir)?;

    let db_path = db_dir.join("sentryavtt.db");
    tracing::info!("Opening database at {}", db_path.display());

    let conn = Connection::open(&db_path)?;

    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA cache_size = -8000;
         PRAGMA busy_timeout = 3000;
         PRAGMA foreign_keys = ON;",
    )?;

    schema::initialize(&conn)?;
    schema::seed_known_threats(&conn)?;

    Ok(conn)
}

/// Thread-safe database handle.
/// The inner `Mutex<Connection>` is necessary because `rusqlite::Connection`
/// is `Send` but not `Sync` (it uses `RefCell` internally for statement cache).
pub struct Database {
    pub conn: Mutex<Connection>,
}

impl Database {
    /// Opens a new database connection and wraps it in a Mutex.
    pub fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let conn = open_database()?;
        Ok(Self { conn: Mutex::new(conn) })
    }
}
