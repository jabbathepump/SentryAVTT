use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub watch_paths: Vec<PathBuf>,
    pub scan_interval_secs: u64,
    pub process_denylist: Vec<String>,
    pub max_file_size_bytes: u64,
    pub quarantine_dir: PathBuf,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            watch_paths: vec![PathBuf::from(r"C:\SentryWatch")],
            scan_interval_secs: 5,
            process_denylist: vec![
                "malware.exe".to_string(),
                "keylogger.exe".to_string(),
                "coinminer.exe".to_string(),
            ],
            max_file_size_bytes: 100 * 1024 * 1024,
            quarantine_dir: PathBuf::from(r"C:\ProgramData\SentryAVTT\Quarantine"),
        }
    }
}

impl AppConfig {
    pub fn load() -> Self {
        let config_path = PathBuf::from(r"C:\ProgramData\SentryAVTT\config.json");
        if config_path.exists() {
            match std::fs::read_to_string(&config_path) {
                Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
                Err(e) => {
                    eprintln!("Failed to read config: {e}; using defaults");
                    Self::default()
                }
            }
        } else {
            Self::default()
        }
    }
}
