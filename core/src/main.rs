mod config;
mod db;
mod ipc;
mod monitor;
mod quarantine;
mod scanner;

use config::AppConfig;
use db::Database;
use ipc::pipe_server::{run_pipe_server, IpcContext};
use monitor::filesystem::spawn_file_watcher;
use monitor::process::spawn_process_scanner;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

#[tokio::main]
async fn main() {
    // ── Windows Service CLI ───────────────────────────────────────────
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--install" => return install_service(),
            "--uninstall" => return uninstall_service(),
            "--update-db" => {
                let url = args.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_FEED_URL);
                let conn = db::open_database().map_err(|e| {
                    eprintln!("Failed to open database: {e}");
                    std::process::exit(1);
                }).unwrap();
                match db::updater::update_from_url(&conn, url) {
                    Ok(count) => {
                        println!("Database updated: {count} signatures added from JSON.");
                    }
                    Err(e) => {
                        eprintln!("Failed to update database: {e}");
                        std::process::exit(1);
                    }
                }
                return;
            }
            "--update-db-from-csv" => {
                let url = args.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_FEED_URL);
                let conn = db::open_database().map_err(|e| {
                    eprintln!("Failed to open database: {e}");
                    std::process::exit(1);
                }).unwrap();
                match db::updater::update_from_csv(&conn, url) {
                    Ok(count) => {
                        println!("Database updated: {count} signatures added from CSV.");
                    }
                    Err(e) => {
                        eprintln!("Failed to update database: {e}");
                        std::process::exit(1);
                    }
                }
                return;
            }
            "--help" | "-h" => {
                println!("SentryAVTT Core Agent v{}", env!("CARGO_PKG_VERSION"));
                println!();
                println!("Usage:");
                println!("  sentryavtt-core                       Run the core agent");
                println!("  sentryavtt-core --install             Register as Windows service");
                println!("  sentryavtt-core --uninstall           Unregister Windows service");
                println!("  sentryavtt-core --update-db [url]     Update threat DB from JSON feed");
                println!("  sentryavtt-core --update-db-from-csv [url]  Update from MalwareBazaar CSV");
                println!("  sentryavtt-core --help                Show this help");
                println!();
                println!("Threat Feed Formats:");
                println!("  JSON:  [{{\"hash\": \"...\", \"threat_name\": \"...\", \"severity\": N}}, ...]");
                println!("  CSV:   MalwareBazaar format (https://bazaar.abuse.ch/export/csv/recent/)");
                println!("  Default URL: {DEFAULT_FEED_URL}");
                return;
            }
            _ => {
                eprintln!("Unknown argument: {} (use --help)", args[1]);
                std::process::exit(1);
            }
        }
    }

    // Detect if running in Session-0 (service context)
    #[cfg(windows)]
    if is_session_zero() {
        eprintln!("Running in Session-0 (service context) — output will be invisible.");
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sentryavtt_core=info".into()),
        )
        .init();

    let config = AppConfig::load();

    tracing::info!("SentryAVTT Core Agent v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Watch paths: {:?}", config.watch_paths);
    tracing::info!("Scan interval: {}s", config.scan_interval_secs);

    // ── Initialize database ──────────────────────────────────────────
    let database = match Database::open() {
        Ok(db) => {
            tracing::info!("Database opened successfully");
            db
        }
        Err(e) => {
            tracing::error!("Failed to open database: {e}");
            eprintln!("FATAL: Cannot open database: {e}");
            std::process::exit(1);
        }
    };

    // Open a second connection for the scanner module (separate from Database,
    // so there is no mutex contention on DB reads during scans).
    match db::open_database().map(scanner::init_db_cache) {
        Ok(_) => tracing::info!("Scanner DB connection initialized"),
        Err(e) => tracing::warn!("Scanner DB connection failed, using fallback hash list: {e}"),
    }

    for path in &config.watch_paths {
        if !path.exists() {
            tracing::warn!("Watch path does not exist, creating: {}", path.display());
            if let Err(e) = std::fs::create_dir_all(path) {
                tracing::error!("Failed to create watch directory: {e}");
                eprintln!(
                    "FATAL: Cannot create watch directory {}: {e}",
                    path.display()
                );
                std::process::exit(1);
            }
        }
    }

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let (alert_tx, mut alert_rx) = mpsc::unbounded_channel();

    // ── File system watcher ──────────────────────────────────────────
    let _file_rx = spawn_file_watcher(&config.watch_paths, shutdown_tx.subscribe());
    tracing::info!("File system watcher spawned");

    // ── Process scanner ──────────────────────────────────────────────
    spawn_process_scanner(
        config.scan_interval_secs,
        config.process_denylist.clone(),
        alert_tx,
        shutdown_tx.subscribe(),
    );
    tracing::info!("Process scanner spawned");

    // ── IPC Named Pipe Server ────────────────────────────────────────
    let ipc_ctx = Arc::new(IpcContext::new(database, shutdown_tx.clone()));
    let ipc_handle = {
        let ctx = ipc_ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = run_pipe_server(ctx).await {
                tracing::error!("IPC server failed: {e}");
            }
        })
    };
    tracing::info!("IPC pipe server spawned");

    // ── Alert handler ────────────────────────────────────────────────
    let alert_handle = tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            tracing::error!(
                "ACTION REQUIRED: Suspicious process — {} (PID {}): {}",
                alert.name,
                alert.pid,
                alert.reason
            );
        }
    });

    // ── Signal handler (Ctrl+C) ──────────────────────────────────────
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        tracing::info!("Ctrl+C received, shutting down...");
        let _ = shutdown_tx.send(());
    });

    tracing::info!("SentryAVTT Core Agent is running. Press Ctrl+C to stop.");

    tokio::select! {
        _ = alert_handle => {},
        _ = ipc_handle => {},
    }

    tracing::info!("SentryAVTT Core Agent shut down gracefully.");
}

// ─── Windows Service Helpers ────────────────────────────────────────────

/// Registers the core agent as a Windows service via sc.exe.
fn install_service() {
    let exe_path = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("sentryavtt-core.exe"));
    let exe_str = exe_path.display().to_string();

    println!("Installing SentryAVTT Core as a Windows service...");
    println!("  Binary: {exe_str}");

    let output = std::process::Command::new("sc.exe")
        .args([
            "create",
            "SentryAVTT",
            &format!("binPath={exe_str}"),
            "start=auto",
            "DisplayName=SentryAVTT Core Agent",
            "description=Real-time antivirus and threat detection engine",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            println!("Service 'SentryAVTT' installed successfully.");
            println!("Start with: sc start SentryAVTT");
            println!("Stop with:  sc stop SentryAVTT");
            println!("Remove with: sentryavtt-core --uninstall");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            eprintln!("Failed to install service: {stderr}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to run sc.exe: {e}");
            std::process::exit(1);
        }
    }
}

const DEFAULT_FEED_URL: &str = "https://bazaar.abuse.ch/export/csv/recent/";

/// Unregisters the Windows service.
fn uninstall_service() {
    println!("Uninstalling SentryAVTT service...");

    // Stop the service first
    let _ = std::process::Command::new("sc.exe")
        .args(["stop", "SentryAVTT"])
        .output();

    let output = std::process::Command::new("sc.exe")
        .args(["delete", "SentryAVTT"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            println!("Service 'SentryAVTT' uninstalled successfully.");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            eprintln!("Failed to uninstall service: {stderr}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to run sc.exe: {e}");
            std::process::exit(1);
        }
    }
}

/// Checks if the current process is running in Session-0 (service context)
/// by querying the session ID via `ProcessIdToSessionId`.
fn is_session_zero() -> bool {
    #[cfg(windows)]
    {
        unsafe extern "system" {
            fn ProcessIdToSessionId(dwProcessId: u32, pSessionId: *mut u32) -> i32;
        }
        unsafe {
            let mut session_id: u32 = 0;
            ProcessIdToSessionId(std::process::id(), &mut session_id) != 0 && session_id == 0
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::time::Duration;

    #[tokio::test]
    async fn test_eicar_detection_flow() {
        let dir = std::env::temp_dir().join("sentryavtt_integration");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let file_path = dir.join("eicar.com");
        let mut f = fs::File::create(&file_path).unwrap();
        f.write_all(
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();

        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        let (_alert_tx, _alert_rx) = mpsc::unbounded_channel::<monitor::process::ProcessAlert>();

        let paths = vec![dir.clone()];
        let _file_rx = spawn_file_watcher(&paths, shutdown_tx.subscribe());

        tokio::time::sleep(Duration::from_millis(2000)).await;

        let result = scanner::scan_file(&file_path);
        assert!(matches!(result, scanner::ScanOutcome::ThreatDetected { .. }));

        let _ = fs::remove_dir_all(&dir);
    }
}
