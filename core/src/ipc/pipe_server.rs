use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;
use futures::SinkExt;
use futures::StreamExt;

use crate::db::Database;
use crate::ipc::message::EnvelopeCodec;
use crate::ipc::proto::{self, Envelope, ScanState, StatusResponse};
use crate::scanner::walker::walk_and_scan;

const PIPE_NAME: &str = r"\\.\pipe\SentryAVTT\main";

/// Shared runtime state for all IPC handlers.
pub struct IpcContext {
    pub version: String,
    pub db: Database,
    pub files_scanned: Arc<std::sync::atomic::AtomicU64>,
    pub threats_blocked: Arc<std::sync::atomic::AtomicU64>,
    pub processes_watched: Arc<std::sync::atomic::AtomicU64>,
    pub _shutdown: broadcast::Sender<()>,
}

impl IpcContext {
    pub fn new(db: Database, shutdown: broadcast::Sender<()>) -> Self {
        Self {
            version: format!("sentryavtt-core/{}", env!("CARGO_PKG_VERSION")),
            db,
            files_scanned: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            threats_blocked: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            processes_watched: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            _shutdown: shutdown,
        }
    }
}

/// Per-connection context: core state + event channel for streaming replies.
struct ClientCtx {
    core: Arc<IpcContext>,
    events: mpsc::UnboundedSender<Envelope>,
}

/// Starts the named pipe server.
pub async fn run_pipe_server(ctx: Arc<IpcContext>) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("IPC server: binding to {PIPE_NAME}");

    loop {
        let pipe = match ServerOptions::new()
            .access_inbound(true)
            .access_outbound(true)
            .first_pipe_instance(true)
            .create(PIPE_NAME)
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to create pipe: {e}");
                sleep(Duration::from_secs(3)).await;
                continue;
            }
        };

        tracing::debug!("Waiting for client...");
        if let Err(_e) = pipe.connect().await {
            sleep(Duration::from_millis(250)).await;
            continue;
        }

        tracing::info!("IPC client connected");

        let client_ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(pipe, client_ctx).await {
                tracing::warn!("Client handler: {e}");
            }
        });
    }
}

async fn handle_client(
    pipe: NamedPipeServer,
    ctx: Arc<IpcContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Envelope>();
    let response_tx = event_tx.clone();
    let client = Arc::new(ClientCtx {
        core: ctx,
        events: event_tx,
    });

    let (reader, writer) = tokio::io::split(pipe);
    let mut read = tokio_util::codec::FramedRead::new(reader, EnvelopeCodec::default());
    let mut write = tokio_util::codec::FramedWrite::new(writer, EnvelopeCodec::default());

    // Task: forward events from channel to the pipe
    let write_task = tokio::spawn(async move {
        crate::ipc::message::announce_ready(&mut write).await;
        while let Some(envelope) = event_rx.recv().await {
            if let Err(e) = write.send(envelope).await {
                tracing::warn!("Pipe write error: {e}");
                break;
            }
        }
    });

    // Read requests from client
    while let Some(frame) = read.next().await {
        let envelope = match frame {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Pipe decode error: {e}");
                continue;
            }
        };

        tracing::debug!("Received: seq={}, type={}", envelope.sequence, envelope.r#type);

        if let Some(response) = route_message(&envelope, client.clone()).await {
            if let Err(e) = response_tx.send(response) {
                tracing::warn!("Failed to queue response: {e}");
                break;
            }
        }
    }

    drop(response_tx);
    let _ = write_task.await;
    tracing::debug!("Client disconnected");
    Ok(())
}

async fn route_message(msg: &Envelope, client: Arc<ClientCtx>) -> Option<Envelope> {
    match &msg.payload {
        Some(crate::ipc::proto::envelope::Payload::GetStatusReq(_)) => {
            Some(build_status(msg.sequence, &client))
        }
        Some(crate::ipc::proto::envelope::Payload::PingReq(_)) => {
            Some(crate::ipc::message::build_pong_response(
                msg.sequence,
                proto::PongResponse {
                    server_time_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                },
            ))
        }
        Some(crate::ipc::proto::envelope::Payload::ScanReq(req)) => {
            let scan_id = uuid::Uuid::new_v4().to_string();
            let target = req.target_path.clone();

            tracing::info!("Scan request: id={scan_id}, path={target}");

            // Acknowledge immediately
            let ack = crate::ipc::message::build_scan_response(
                msg.sequence,
                proto::ScanResponse {
                    scan_id: scan_id.clone(),
                    state: ScanState::Queued as i32,
                    files_queued: 0,
                },
            );

            // Spawn the actual scan in the background with an owning Arc
            tokio::spawn(async move {
                perform_scan(&scan_id, &target, client).await;
            });

            Some(ack)
        }
        Some(crate::ipc::proto::envelope::Payload::CancelScanReq(req)) => {
            tracing::info!("Cancel scan: id={}", req.scan_id);
            Some(crate::ipc::message::build_cancel_response(
                msg.sequence,
                proto::CancelScanResponse {
                    scan_id: req.scan_id.clone(),
                    ok: true,
                    message: "cancellation acknowledged".to_string(),
                },
            ))
        }
        Some(crate::ipc::proto::envelope::Payload::QuarantineListReq(_)) => {
            match crate::quarantine::list_quarantine(&client.core.db.conn) {
                Ok(entries) => {
                    let proto_entries: Vec<_> = entries
                        .into_iter()
                        .map(|e| crate::ipc::proto::QuarantineEntry {
                            id: e.id,
                            original_path: e.original_path,
                            quarantined_path: e.quarantined_path,
                            quarantined_at: e.quarantined_at,
                            hash: e.hash,
                            threat_name: e.threat_name,
                            severity: e.severity,
                            status: e.status,
                        })
                        .collect();
                    Some(crate::ipc::message::build_quarantine_list_response(
                        msg.sequence,
                        proto_entries,
                    ))
                }
                Err(e) => Some(crate::ipc::message::build_error(
                    msg.sequence,
                    "QUARANTINE_LIST_ERR",
                    &e,
                )),
            }
        }
        Some(crate::ipc::proto::envelope::Payload::QuarantineRestoreReq(req)) => {
            let id = req.id.clone();
            match crate::quarantine::restore_file(&client.core.db.conn, &id) {
                Ok(_) => Some(crate::ipc::message::build_quarantine_restore_response(
                    msg.sequence,
                    &id,
                    true,
                    "file restored",
                )),
                Err(e) => Some(crate::ipc::message::build_quarantine_restore_response(
                    msg.sequence,
                    &id,
                    false,
                    &e,
                )),
            }
        }
        Some(crate::ipc::proto::envelope::Payload::QuarantineDeleteReq(req)) => {
            let id = req.id.clone();
            match crate::quarantine::delete_file(&client.core.db.conn, &id) {
                Ok(_) => Some(crate::ipc::message::build_quarantine_delete_response(
                    msg.sequence,
                    &id,
                    true,
                    "file deleted",
                )),
                Err(e) => Some(crate::ipc::message::build_quarantine_delete_response(
                    msg.sequence,
                    &id,
                    false,
                    &e,
                )),
            }
        }
        Some(crate::ipc::proto::envelope::Payload::Error(err)) => {
            tracing::error!("Client error: [{}/{}]", err.code, err.message);
            None
        }
        _ => {
            tracing::warn!("Unhandled payload (seq={})", msg.sequence);
            Some(crate::ipc::message::build_error(
                msg.sequence,
                "UNHANDLED",
                "message type not implemented",
            ))
        }
    }
}

async fn perform_scan(scan_id: &str, target_path: &str, client: Arc<ClientCtx>) {
    let path = Path::new(target_path);

    if !path.exists() {
        let _ = client.events.send(crate::ipc::message::build_error(
            0,
            "SCAN_ERR",
            &format!("Path not found: {target_path}"),
        ));
        return;
    }

    // Record scan start
    if let Ok(conn) = client.core.db.conn.lock() {
        if let Err(e) = crate::db::scan_history::start_scan(&conn, scan_id, target_path) {
            tracing::warn!("DB: failed to record scan start: {e}");
        }
    }

    let (files_scanned, threats_found) = walk_and_scan(
        path,
        &client.core.db,
        |scanned, threats, _total, current| {
            let _ = client.events.send(crate::ipc::message::build_scan_progress(
                scan_id,
                scanned as u32,
                0,
                threats as u32,
                current,
                0.0,
            ));

            // Update atomic counters on context
            client
                .core
                .files_scanned
                .store(scanned, std::sync::atomic::Ordering::Relaxed);
            client
                .core
                .threats_blocked
                .store(threats, std::sync::atomic::Ordering::Relaxed);
        },
        |hash, threat_name, severity, threat_path| {
            let _ = client.events.send(crate::ipc::message::build_threat_detected(
                &threat_path.display().to_string(),
                hash,
                threat_name,
                severity,
            ));
        },
    );

    // Mark scan complete
    if let Ok(conn) = client.core.db.conn.lock() {
        let status = "completed";
        if let Err(e) = crate::db::scan_history::complete_scan(
            &conn, scan_id, files_scanned, threats_found, status,
        ) {
            tracing::warn!("DB: failed to record scan completion: {e}");
        }
    }

    // Send completion event
    let _ = client.events.send(crate::ipc::message::build_scan_progress(
        scan_id,
        files_scanned as u32,
        files_scanned as u32,
        threats_found as u32,
        "",
        100.0,
    ));

    tracing::info!(
        "Scan completed: id={scan_id}, files={files_scanned}, threats={threats_found}"
    );
}

fn build_status(seq: u64, client: &Arc<ClientCtx>) -> Envelope {
    let threats_loaded = client.core.db.conn.lock().ok()
        .and_then(|conn| crate::db::threats::threat_count(&conn).ok())
        .unwrap_or(0);

    let quarantine_count = crate::quarantine::quarantine_count(&client.core.db.conn).unwrap_or(0);

    crate::ipc::message::build_status_response(
        seq,
        StatusResponse {
            version: client.core.version.clone(),
            active_scans: 0,
            files_scanned: client.core.files_scanned.load(std::sync::atomic::Ordering::Relaxed),
            threats_blocked: client.core.threats_blocked.load(std::sync::atomic::Ordering::Relaxed),
            processes_watched: client
                .core
                .processes_watched
                .load(std::sync::atomic::Ordering::Relaxed),
            quarantine_count,
            service_running: true,
            signature_age: format!("{threats_loaded} signatures"),
        },
    )
}
