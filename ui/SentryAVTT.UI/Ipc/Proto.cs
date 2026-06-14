using ProtoBuf;

namespace SentryAVTT.UI.Ipc;

// ─── Enums ─────────────────────────────────────────────────────────────

public enum MessageType
{
    Unspecified = 0,
    Request = 1,
    Response = 2,
    Event = 3,
}

public enum ScanState
{
    Unspecified = 0,
    Queued = 1,
    Running = 2,
    Completed = 3,
    Cancelled = 4,
    Error = 5,
}

// ─── Envelope (top-level message) ──────────────────────────────────────

[ProtoContract]
public class Envelope
{
    [ProtoMember(1)] public ulong Sequence { get; set; }
    [ProtoMember(2)] public ulong TimestampMs { get; set; }
    [ProtoMember(3)] public MessageType Type { get; set; }

    // Requests (UI -> Core)
    [ProtoMember(10)] public ScanRequest? ScanReq { get; set; }
    [ProtoMember(11)] public CancelScanRequest? CancelScanReq { get; set; }
    [ProtoMember(12)] public GetStatusRequest? GetStatusReq { get; set; }
    [ProtoMember(13)] public PingRequest? PingReq { get; set; }
    [ProtoMember(14)] public QuarantineListRequest? QuarantineListReq { get; set; }
    [ProtoMember(15)] public QuarantineRestoreRequest? QuarantineRestoreReq { get; set; }
    [ProtoMember(16)] public QuarantineDeleteRequest? QuarantineDeleteReq { get; set; }

    // Responses (Core -> UI)
    [ProtoMember(20)] public ScanResponse? ScanRes { get; set; }
    [ProtoMember(21)] public CancelScanResponse? CancelScanRes { get; set; }
    [ProtoMember(22)] public StatusResponse? StatusRes { get; set; }
    [ProtoMember(23)] public PongResponse? PongRes { get; set; }
    [ProtoMember(24)] public QuarantineListResponse? QuarantineListRes { get; set; }
    [ProtoMember(25)] public QuarantineRestoreResponse? QuarantineRestoreRes { get; set; }
    [ProtoMember(26)] public QuarantineDeleteResponse? QuarantineDeleteRes { get; set; }

    // Events (Core -> UI, unsolicited)
    [ProtoMember(30)] public ThreatDetectedEvent? ThreatDetected { get; set; }
    [ProtoMember(31)] public ScanProgressEvent? ScanProgress { get; set; }
    [ProtoMember(32)] public CoreStatusEvent? CoreStatus { get; set; }

    // Errors
    [ProtoMember(40)] public ErrorMessage? Error { get; set; }
}

// ─── Requests ──────────────────────────────────────────────────────────

[ProtoContract]
public class GetStatusRequest { }

[ProtoContract]
public class PingRequest { }

[ProtoContract]
public class ScanRequest
{
    [ProtoMember(1)] public string TargetPath { get; set; } = "";
    [ProtoMember(2)] public bool Recursive { get; set; }
}

[ProtoContract]
public class CancelScanRequest
{
    [ProtoMember(1)] public string ScanId { get; set; } = "";
}

// ─── Responses ─────────────────────────────────────────────────────────

[ProtoContract]
public class StatusResponse
{
    [ProtoMember(1)] public string Version { get; set; } = "";
    [ProtoMember(2)] public int ActiveScans { get; set; }
    [ProtoMember(3)] public ulong FilesScanned { get; set; }
    [ProtoMember(4)] public ulong ThreatsBlocked { get; set; }
    [ProtoMember(5)] public ulong ProcessesWatched { get; set; }
    [ProtoMember(6)] public ulong QuarantineCount { get; set; }
    [ProtoMember(7)] public bool ServiceRunning { get; set; }
    [ProtoMember(8)] public string SignatureAge { get; set; } = "";
}

[ProtoContract]
public class PongResponse
{
    [ProtoMember(1)] public ulong ServerTimeMs { get; set; }
}

[ProtoContract]
public class ScanResponse
{
    [ProtoMember(1)] public string ScanId { get; set; } = "";
    [ProtoMember(2)] public ScanState State { get; set; }
    [ProtoMember(3)] public uint FilesQueued { get; set; }
}

[ProtoContract]
public class CancelScanResponse
{
    [ProtoMember(1)] public string ScanId { get; set; } = "";
    [ProtoMember(2)] public bool Ok { get; set; }
    [ProtoMember(3)] public string Message { get; set; } = "";
}

// ─── Events ────────────────────────────────────────────────────────────

[ProtoContract]
public class ScanProgressEvent
{
    [ProtoMember(1)] public string ScanId { get; set; } = "";
    [ProtoMember(2)] public uint FilesScanned { get; set; }
    [ProtoMember(3)] public uint FilesTotal { get; set; }
    [ProtoMember(4)] public uint ThreatsFound { get; set; }
    [ProtoMember(5)] public string CurrentFile { get; set; } = "";
    [ProtoMember(6)] public double ProgressPct { get; set; }
}

[ProtoContract]
public class ThreatDetectedEvent
{
    [ProtoMember(1)] public string Path { get; set; } = "";
    [ProtoMember(2)] public string Hash { get; set; } = "";
    [ProtoMember(3)] public string ThreatName { get; set; } = "";
    [ProtoMember(4)] public ThreatSeverity Severity { get; set; }
}

public enum ThreatSeverity
{
    Unspecified = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

[ProtoContract]
public class CoreStatusEvent
{
    [ProtoMember(1)] public CoreState State { get; set; }
    [ProtoMember(2)] public string Detail { get; set; } = "";
}

public enum CoreState
{
    Unspecified = 0,
    Starting = 1,
    Ready = 2,
    Busy = 3,
    Error = 4,
    ShuttingDown = 5,
}

[ProtoContract]
public class ErrorMessage
{
    [ProtoMember(1)] public string Code { get; set; } = "";
    [ProtoMember(2)] public string Message { get; set; } = "";
}

// ─── Quarantine ───────────────────────────────────────────────────────

[ProtoContract]
public class QuarantineListRequest { }

[ProtoContract]
public class QuarantineEntry
{
    [ProtoMember(1)] public string Id { get; set; } = "";
    [ProtoMember(2)] public string OriginalPath { get; set; } = "";
    [ProtoMember(3)] public string QuarantinedPath { get; set; } = "";
    [ProtoMember(4)] public string QuarantinedAt { get; set; } = "";
    [ProtoMember(5)] public string Hash { get; set; } = "";
    [ProtoMember(6)] public string ThreatName { get; set; } = "";
    [ProtoMember(7)] public int Severity { get; set; }
    [ProtoMember(8)] public string Status { get; set; } = "";
}

[ProtoContract]
public class QuarantineListResponse
{
    [ProtoMember(1)] public List<QuarantineEntry> Entries { get; set; } = new();
}

[ProtoContract]
public class QuarantineRestoreRequest
{
    [ProtoMember(1)] public string Id { get; set; } = "";
}

[ProtoContract]
public class QuarantineRestoreResponse
{
    [ProtoMember(1)] public string Id { get; set; } = "";
    [ProtoMember(2)] public bool Ok { get; set; }
    [ProtoMember(3)] public string Message { get; set; } = "";
}

[ProtoContract]
public class QuarantineDeleteRequest
{
    [ProtoMember(1)] public string Id { get; set; } = "";
}

[ProtoContract]
public class QuarantineDeleteResponse
{
    [ProtoMember(1)] public string Id { get; set; } = "";
    [ProtoMember(2)] public bool Ok { get; set; }
    [ProtoMember(3)] public string Message { get; set; } = "";
}
