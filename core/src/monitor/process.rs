use crate::scanner::scan_file;
use std::path::PathBuf;
use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::sync::broadcast;

pub struct ProcessScanner {
    system: System,
    denylist: Vec<String>,
    known_pids: Vec<Pid>,
}

impl ProcessScanner {
    pub fn new(denylist: Vec<String>) -> Self {
        Self {
            system: System::new(),
            denylist,
            known_pids: Vec::new(),
        }
    }

    pub fn scan_once(&mut self) -> Vec<ProcessAlert> {
        let mut alerts = Vec::new();

        self.system
            .refresh_processes(ProcessesToUpdate::All, true);
        let current_pids: std::collections::HashSet<Pid> =
            self.system.processes().keys().copied().collect();

        let new_pids: Vec<Pid> = current_pids
            .difference(&self.known_pids.iter().copied().collect())
            .copied()
            .collect();

        for &pid in &new_pids {
            if let Some(process) = self.system.process(pid) {
                let name = process.name().to_string_lossy().to_string();
                let path = process.exe().map(|p| p.to_path_buf());

                if self.denylist.iter().any(|bad| {
                    name.eq_ignore_ascii_case(bad)
                        || path
                            .as_ref()
                            .and_then(|p| p.file_name())
                            .and_then(|n| n.to_str())
                            .is_some_and(|s| s.eq_ignore_ascii_case(bad))
                }) {
                    tracing::error!(
                        "Blocklisted process detected: {name} (PID {})",
                        pid.as_u32()
                    );
                    alerts.push(ProcessAlert {
                        pid: pid.as_u32(),
                        name: name.clone(),
                        path: path.clone(),
                        reason: "name matches denylist".to_string(),
                    });
                    continue;
                }

                if let Some(ref exe_path) = path {
                    if exe_path.exists() {
                        let outcome = scan_file(exe_path);
                        if matches!(outcome, crate::scanner::ScanOutcome::ThreatDetected { .. })
                        {
                            tracing::error!(
                                "Threat detected in running process: {name} (PID {})",
                                pid.as_u32()
                            );
                            alerts.push(ProcessAlert {
                                pid: pid.as_u32(),
                                name: name.clone(),
                                path: Some(exe_path.clone()),
                                reason: "SHA-256 hash matches threat database".to_string(),
                            });
                        }
                    }
                }
            }
        }

        self.known_pids = current_pids.into_iter().collect();
        alerts
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProcessAlert {
    pub pid: u32,
    pub name: String,
    pub path: Option<PathBuf>,
    pub reason: String,
}

pub fn spawn_process_scanner(
    interval_secs: u64,
    denylist: Vec<String>,
    alert_tx: tokio::sync::mpsc::UnboundedSender<ProcessAlert>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut scanner = ProcessScanner::new(denylist);

        tracing::info!(
            "Process scanner started (interval: {interval_secs}s)"
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {
                    let alerts = scanner.scan_once();
                    for alert in alerts {
                        let _ = alert_tx.send(alert);
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("Process scanner shutting down");
                    break;
                }
            }
        }
    });
}
