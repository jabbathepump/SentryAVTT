namespace SentryAVTT.UI.Models;

public enum ScanStatus
{
    Idle,
    Scanning,
    Clean,
    ThreatDetected,
    Error
}

public sealed class ProcessEntry
{
    public uint Pid { get; init; }
    public string Name { get; init; } = "";
    public string Path { get; init; } = "";
    public string Status { get; init; } = "Pending";
    public string ThreatHash { get; init; } = "";
    public DateTime DetectedAt { get; init; } = DateTime.UtcNow;
}

public sealed class DashboardStats
{
    public long FilesScanned { get; set; }
    public long ThreatsBlocked { get; set; }
    public long ProcessesWatched { get; set; }
    public long QuarantineCount { get; set; }
    public DateTime LastScanTime { get; set; }
    public string Version { get; init; } = "0.1.0";
    public string SignatureAge { get; set; } = "Unknown";
}
