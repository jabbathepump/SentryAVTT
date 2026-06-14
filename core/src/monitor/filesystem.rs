use crate::scanner::scan_file;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use tokio::sync::broadcast;

#[allow(dead_code)]
pub enum WatchEvent {
    FileCreated(String),
    FileModified(String),
    WatcherError(String),
}

pub fn spawn_file_watcher(
    watch_paths: &[std::path::PathBuf],
    shutdown_rx: broadcast::Receiver<()>,
) -> mpsc::Receiver<WatchEvent> {
    let (tx, rx) = mpsc::channel::<WatchEvent>();
    let paths = watch_paths.to_vec();

    std::thread::spawn(move || {
        let (notify_tx, notify_rx) = mpsc::channel::<notify::Result<Event>>();

        let mut watcher = match RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                let _ = notify_tx.send(res);
            },
            Config::default(),
        ) {
            Ok(w) => w,
            Err(e) => {
                let _ = tx.send(WatchEvent::WatcherError(e.to_string()));
                return;
            }
        };

        for path in &paths {
            if path.exists() {
                if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                    tracing::warn!("Failed to watch {}: {e}", path.display());
                    let _ = tx.send(WatchEvent::WatcherError(format!(
                        "Cannot watch {}: {e}",
                        path.display()
                    )));
                } else {
                    tracing::info!("Watching: {}", path.display());
                }
            } else {
                tracing::warn!("Watch path does not exist: {}", path.display());
                let _ = tx.send(WatchEvent::WatcherError(format!(
                    "Path not found: {}",
                    path.display()
                )));
            }
        }

        let mut shutdown_rx = shutdown_rx;
        loop {
            if shutdown_rx.try_recv().is_ok() {
                tracing::info!("File watcher shutting down");
                break;
            }

            match notify_rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(Ok(event)) => {
                    let event_str = match event.kind {
                        EventKind::Create(_) => "created",
                        EventKind::Modify(_) => "modified",
                        _ => continue,
                    };

                    for path in event.paths {
                        if should_skip(&path) {
                            continue;
                        }
                        tracing::info!("File {event_str}: {}", path.display());

                        let watch_event = match event.kind {
                            EventKind::Create(_) => WatchEvent::FileCreated(path.display().to_string()),
                            EventKind::Modify(_) => WatchEvent::FileModified(path.display().to_string()),
                            _ => continue,
                        };

                        let _ = tx.send(watch_event);

                        // Run the scan inline on the file
                        let outcome = scan_file(&path);
                        if matches!(outcome, crate::scanner::ScanOutcome::ThreatDetected { .. }) {
                            tracing::error!(
                                "THREAT CONFIRMED via watcher: {}",
                                path.display()
                            );
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!("Notify error: {e}");
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    tracing::error!("Notify channel disconnected");
                    break;
                }
            }
        }
    });

    rx
}

fn should_skip(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if name.starts_with('.') || name.ends_with(".tmp") || name.ends_with(".bak") {
        return true;
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let skip_extensions = [
            "log", "dmp", "cache", "idx", "lock",
        ];
        if skip_extensions.contains(&ext.to_ascii_lowercase().as_str()) {
            return true;
        }
    }

    false
}
