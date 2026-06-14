using SentryAVTT.UI.Models;

namespace SentryAVTT.UI.Services;

public sealed class ScanService : IDisposable
{
    private readonly CancellationTokenSource _cts = new();
    private bool _isScanning;

    public bool IsScanning => _isScanning;

    public event Action<ProcessEntry>? ProcessDiscovered;
    public event Action<DashboardStats>? StatsUpdated;
    public event Action<ScanStatus>? StatusChanged;
    public event Action<string>? ScanError;

    public async Task StartQuickScanAsync()
    {
        if (_isScanning) return;
        _isScanning = true;

        StatusChanged?.Invoke(ScanStatus.Scanning);

        try
        {
            var stats = new DashboardStats();

            await foreach (var entry in SimulateScanAsync(_cts.Token))
            {
                ProcessDiscovered?.Invoke(entry);
                stats.FilesScanned++;

                if (!string.IsNullOrEmpty(entry.ThreatHash))
                {
                    stats.ThreatsBlocked++;
                }

                StatsUpdated?.Invoke(stats);
            }

            stats.LastScanTime = DateTime.UtcNow;
            StatsUpdated?.Invoke(stats);
            StatusChanged?.Invoke(stats.ThreatsBlocked > 0
                ? ScanStatus.ThreatDetected
                : ScanStatus.Clean);
        }
        catch (OperationCanceledException)
        {
            StatusChanged?.Invoke(ScanStatus.Idle);
        }
        catch (Exception ex)
        {
            ScanError?.Invoke(ex.Message);
            StatusChanged?.Invoke(ScanStatus.Error);
        }
        finally
        {
            _isScanning = false;
        }
    }

    public void CancelScan()
    {
        _cts.Cancel();
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
    }

    private static async IAsyncEnumerable<ProcessEntry> SimulateScanAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var simulated = new[]
        {
            new ProcessEntry { Pid = 1234, Name = "svchost.exe", Path = @"C:\Windows\System32\svchost.exe", Status = "Clean" },
            new ProcessEntry { Pid = 5678, Name = "explorer.exe", Path = @"C:\Windows\explorer.exe", Status = "Clean" },
            new ProcessEntry { Pid = 9012, Name = "chrome.exe", Path = @"C:\Program Files\Google\Chrome\chrome.exe", Status = "Clean" },
            new ProcessEntry { Pid = 3456, Name = "suspicious.dll", Path = @"C:\Users\test\AppData\Local\Temp\suspicious.dll", Status = "Threat", ThreatHash = "e1105070ba828007508566e28a2b8d4c" },
            new ProcessEntry { Pid = 7890, Name = "powershell.exe", Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", Status = "Clean" },
            new ProcessEntry { Pid = 1111, Name = "unknown.exe", Path = @"C:\Users\test\Downloads\unknown.exe", Status = "Quarantined", ThreatHash = "a3a5e7f4d8b9c1e2f3a4b5c6d7e8f9a0" },
        };

        foreach (var entry in simulated)
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(800, ct);
            yield return entry;
        }
    }
}
