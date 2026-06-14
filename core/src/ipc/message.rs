use bytes::BytesMut;
use futures::SinkExt;
use prost::Message;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

use crate::ipc::proto::{self, envelope, Envelope, MessageType};

/// Length-delimited codec framing protobuf Envelope messages.
/// Wire format: [4-byte LE payload length] [protobuf bytes].
pub struct EnvelopeCodec {
    inner: LengthDelimitedCodec,
}

impl Default for EnvelopeCodec {
    fn default() -> Self {
        Self {
            inner: LengthDelimitedCodec::builder()
                .max_frame_length(16 * 1024 * 1024)
                .new_codec(),
        }
    }
}

impl Decoder for EnvelopeCodec {
    type Item = Envelope;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src) {
            Ok(Some(frame)) => match Envelope::decode(frame) {
                Ok(envelope) => Ok(Some(envelope)),
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("protobuf decode: {e}"),
                )),
            },
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl Encoder<Envelope> for EnvelopeCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Envelope, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut payload = BytesMut::new();
        item.encode(&mut payload).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("protobuf encode: {e}"),
            )
        })?;
        self.inner
            .encode(payload.freeze(), dst)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }
}

// ─── Envelope builder helpers ──────────────────────────────────────────

fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn build_status_response(seq: u64, status: proto::StatusResponse) -> Envelope {
    Envelope {
        sequence: seq,
        timestamp_ms: timestamp_now(),
        r#type: MessageType::Response as i32,
        payload: Some(envelope::Payload::StatusRes(status)),
    }
}

pub fn build_pong_response(seq: u64, pong: proto::PongResponse) -> Envelope {
    Envelope {
        sequence: seq,
        timestamp_ms: timestamp_now(),
        r#type: MessageType::Response as i32,
        payload: Some(envelope::Payload::PongRes(pong)),
    }
}

pub fn build_scan_response(seq: u64, resp: proto::ScanResponse) -> Envelope {
    Envelope {
        sequence: seq,
        timestamp_ms: timestamp_now(),
        r#type: MessageType::Response as i32,
        payload: Some(envelope::Payload::ScanRes(resp)),
    }
}

pub fn build_cancel_response(seq: u64, resp: proto::CancelScanResponse) -> Envelope {
    Envelope {
        sequence: seq,
        timestamp_ms: timestamp_now(),
        r#type: MessageType::Response as i32,
        payload: Some(envelope::Payload::CancelScanRes(resp)),
    }
}

pub fn build_error(seq: u64, code: &str, message: &str) -> Envelope {
    Envelope {
        sequence: seq,
        timestamp_ms: timestamp_now(),
        r#type: MessageType::Response as i32,
        payload: Some(envelope::Payload::Error(proto::ErrorMessage {
            code: code.to_string(),
            message: message.to_string(),
        })),
    }
}

pub fn build_scan_progress(
    scan_id: &str,
    files_scanned: u32,
    files_total: u32,
    threats_found: u32,
    current_file: &str,
    progress_pct: f64,
) -> Envelope {
    Envelope {
        sequence: 0,
        timestamp_ms: timestamp_now(),
        r#type: MessageType::Event as i32,
        payload: Some(envelope::Payload::ScanProgress(proto::ScanProgress {
            scan_id: scan_id.to_string(),
            files_scanned,
            files_total,
            threats_found,
            current_file: current_file.to_string(),
            progress_pct,
        })),
    }
}

pub fn build_threat_detected(path: &str, hash: &str, threat_name: &str, severity: i32) -> Envelope {
    Envelope {
        sequence: 0,
        timestamp_ms: timestamp_now(),
        r#type: MessageType::Event as i32,
        payload: Some(envelope::Payload::ThreatDetected(proto::ThreatDetected {
            path: path.to_string(),
            hash: hash.to_string(),
            threat_name: threat_name.to_string(),
            severity,
        })),
    }
}

pub fn build_core_status(state: i32, detail: &str) -> Envelope {
    Envelope {
        sequence: 0,
        timestamp_ms: timestamp_now(),
        r#type: MessageType::Event as i32,
        payload: Some(envelope::Payload::CoreStatus(proto::CoreStatus {
            state,
            detail: detail.to_string(),
        })),
    }
}

// ─── Quarantine builder helpers ──────────────────────────────────────

pub fn build_quarantine_list_response(seq: u64, entries: Vec<proto::QuarantineEntry>) -> Envelope {
    Envelope {
        sequence: seq,
        timestamp_ms: timestamp_now(),
        r#type: MessageType::Response as i32,
        payload: Some(envelope::Payload::QuarantineListRes(
            proto::QuarantineListResponse { entries },
        )),
    }
}

pub fn build_quarantine_restore_response(seq: u64, id: &str, ok: bool, message: &str) -> Envelope {
    Envelope {
        sequence: seq,
        timestamp_ms: timestamp_now(),
        r#type: MessageType::Response as i32,
        payload: Some(envelope::Payload::QuarantineRestoreRes(
            proto::QuarantineRestoreResponse {
                id: id.to_string(),
                ok,
                message: message.to_string(),
            },
        )),
    }
}

pub fn build_quarantine_delete_response(seq: u64, id: &str, ok: bool, message: &str) -> Envelope {
    Envelope {
        sequence: seq,
        timestamp_ms: timestamp_now(),
        r#type: MessageType::Response as i32,
        payload: Some(envelope::Payload::QuarantineDeleteRes(
            proto::QuarantineDeleteResponse {
                id: id.to_string(),
                ok,
                message: message.to_string(),
            },
        )),
    }
}

pub async fn announce_ready<S, E>(write: &mut S)
where
    S: futures::Sink<Envelope, Error = E> + Unpin,
    E: std::fmt::Display,
{
    let msg = build_core_status(
        proto::core_status::State::Ready as i32,
        "Core agent online, ready for commands",
    );
    if let Err(e) = write.send(msg).await {
        tracing::warn!("Failed to send ready event: {e}");
    }
}
