using System.IO;
using SentryAVTT.UI.Ipc;
using SentryAVTT.UI.Models;

namespace SentryAVTT.UI.Services;

/// <summary>
/// High-level IPC service that bridges named pipe messages to the UI layer.
/// Handles connection lifecycle, request/response correlation, and event dispatch.
/// </summary>
public sealed class IpcService : IDisposable
{
    private readonly PipeClient _pipe = new();
    private bool _connected;

    public event Action<DashboardStats>? StatsReceived;
    public event Action<ProcessEntry>? ThreatDetected;
    public event Action<ScanProgressEvent>? ScanProgressReceived;
    public event Action<bool>? ConnectionStateChanged;
    public event Action<string>? ErrorOccurred;
    public event Action<List<QuarantineEntry>>? QuarantineListReceived;

    public bool IsConnected => _connected;

    public async Task ConnectAsync()
    {
        if (_connected) return;

        _pipe.MessageReceived += OnMessage;
        _pipe.Disconnected += OnDisconnected;
        _pipe.Error += OnError;

        try
        {
            await _pipe.ConnectAsync();
            _connected = true;
            ConnectionStateChanged?.Invoke(true);

            // Send initial status request to verify handshake
            await RequestStatusAsync();
        }
        catch
        {
            _connected = false;
            ConnectionStateChanged?.Invoke(false);
            throw;
        }
    }

    public async Task RequestStatusAsync()
    {
        var req = new Envelope
        {
            Type = MessageType.Request,
            GetStatusReq = new GetStatusRequest()
        };
        await _pipe.SendRequestAsync(req);
    }

    public async Task RequestScanAsync(string path, bool recursive)
    {
        var req = new Envelope
        {
            Type = MessageType.Request,
            ScanReq = new ScanRequest
            {
                TargetPath = path,
                Recursive = recursive
            }
        };
        await _pipe.SendRequestAsync(req);
    }

    public async Task RequestQuarantineListAsync()
    {
        var req = new Envelope
        {
            Type = MessageType.Request,
            QuarantineListReq = new QuarantineListRequest()
        };
        await _pipe.SendRequestAsync(req);
    }

    public async Task RequestQuarantineRestoreAsync(string id)
    {
        var req = new Envelope
        {
            Type = MessageType.Request,
            QuarantineRestoreReq = new QuarantineRestoreRequest { Id = id }
        };
        await _pipe.SendRequestAsync(req);
    }

    public async Task RequestQuarantineDeleteAsync(string id)
    {
        var req = new Envelope
        {
            Type = MessageType.Request,
            QuarantineDeleteReq = new QuarantineDeleteRequest { Id = id }
        };
        await _pipe.SendRequestAsync(req);
    }

    public async Task CancelScanAsync(string scanId)
    {
        var req = new Envelope
        {
            Type = MessageType.Request,
            CancelScanReq = new CancelScanRequest { ScanId = scanId }
        };
        await _pipe.SendRequestAsync(req);
    }

    public void Disconnect()
    {
        _pipe.MessageReceived -= OnMessage;
        _pipe.Disconnected -= OnDisconnected;
        _pipe.Error -= OnError;
        _pipe.Disconnect();
        _connected = false;
        ConnectionStateChanged?.Invoke(false);
    }

    private void OnMessage(Envelope envelope)
    {
        switch (envelope.Type)
        {
            case MessageType.Response:
                HandleResponse(envelope);
                break;
            case MessageType.Event:
                HandleEvent(envelope);
                break;
        }
    }

    private void HandleResponse(Envelope envelope)
    {
        if (envelope.StatusRes is { } status)
        {
            StatsReceived?.Invoke(new DashboardStats
            {
                FilesScanned = (long)status.FilesScanned,
                ThreatsBlocked = (long)status.ThreatsBlocked,
                ProcessesWatched = (long)status.ProcessesWatched,
                QuarantineCount = (long)status.QuarantineCount,
                LastScanTime = DateTime.UtcNow,
                Version = status.Version,
                SignatureAge = status.SignatureAge
            });
        }
        else if (envelope.ScanRes is { } scan)
        {
            // Scan accepted — UI could show scan ID
        }
        else if (envelope.QuarantineListRes is { } qList)
        {
            QuarantineListReceived?.Invoke(qList.Entries);
        }
        else if (envelope.QuarantineRestoreRes is { } qRestore)
        {
            if (!qRestore.Ok)
                ErrorOccurred?.Invoke($"Restore failed: {qRestore.Message}");
        }
        else if (envelope.QuarantineDeleteRes is { } qDelete)
        {
            if (!qDelete.Ok)
                ErrorOccurred?.Invoke($"Delete failed: {qDelete.Message}");
        }
        else if (envelope.Error is { } err)
        {
            ErrorOccurred?.Invoke($"[{err.Code}] {err.Message}");
        }
    }

    private void HandleEvent(Envelope envelope)
    {
        if (envelope.ScanProgress is { } progress)
        {
            ScanProgressReceived?.Invoke(progress);
        }
        else if (envelope.ThreatDetected is { } threat)
        {
            ThreatDetected?.Invoke(new ProcessEntry
            {
                Pid = 0,
                Name = Path.GetFileName(threat.Path),
                Path = threat.Path,
                Status = "Threat",
                ThreatHash = threat.Hash,
                DetectedAt = DateTime.UtcNow
            });
        }
        else if (envelope.CoreStatus is { } core)
        {
            if (core.State == CoreState.Error)
                ErrorOccurred?.Invoke($"Core error: {core.Detail}");
        }
    }

    private void OnDisconnected(string reason)
    {
        _connected = false;
        ConnectionStateChanged?.Invoke(false);
    }

    private void OnError(string error)
    {
        ErrorOccurred?.Invoke(error);
    }

    public void Dispose()
    {
        _pipe.Dispose();
    }
}
