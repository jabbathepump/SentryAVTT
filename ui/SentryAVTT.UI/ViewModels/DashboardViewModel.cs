using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;
using SentryAVTT.UI.Models;
using SentryAVTT.UI.Services;
using SentryAVTT.UI.Ipc;

namespace SentryAVTT.UI.ViewModels;

public sealed class DashboardViewModel : INotifyPropertyChanged
{
    private readonly ScanService _scanner;
    private ScanStatus _status = ScanStatus.Idle;
    private string _statusText = "SentryAVTT is ready";
    private string _statusGlyph = "\uE734";
    private Brush _statusColor = new SolidColorBrush(Color.FromRgb(156, 163, 175));
    private DashboardStats _stats = new();
    private bool _isScanning;
    private bool _showAdminConsole;
    private CancellationTokenSource? _scanCts;

    public DashboardViewModel(ScanService scanner)
    {
        _scanner = scanner;

        _scanner.ProcessDiscovered += OnProcessDiscovered;
        _scanner.StatsUpdated += OnStatsUpdated;
        _scanner.StatusChanged += OnStatusChanged;
        _scanner.ScanError += OnScanError;
    }

    public ScanStatus Status { get => _status; private set => SetField(ref _status, value); }
    public DashboardStats Stats { get => _stats; private set => SetField(ref _stats, value); }
    public bool IsScanning { get => _isScanning; private set => SetField(ref _isScanning, value); }

    public string StatusText
    {
        get => _statusText;
        private set => SetField(ref _statusText, value);
    }

    public string StatusGlyph
    {
        get => _statusGlyph;
        private set => SetField(ref _statusGlyph, value);
    }

    public Brush StatusColor
    {
        get => _statusColor;
        private set => SetField(ref _statusColor, value);
    }

    public bool ShowAdminConsole
    {
        get => _showAdminConsole;
        set
        {
            if (SetField(ref _showAdminConsole, value))
            {
                AdminConsoleVisibilityChanged?.Invoke(value);
                OnPropertyChanged(nameof(AdminConsoleLabel));
            }
        }
    }

    public string AdminConsoleLabel => _showAdminConsole ? "Hide Admin Console" : "Show Admin Console";

    public event PropertyChangedEventHandler? PropertyChanged;
    public event Action<bool>? AdminConsoleVisibilityChanged;
    public event Action<ProcessEntry>? NewProcessEntry;

    public async Task StartScanAsync()
    {
        if (IsScanning) return;
        _scanCts = new CancellationTokenSource();
        IsScanning = true;
        await _scanner.StartQuickScanAsync();
    }

    public void CancelScan()
    {
        _scanCts?.Cancel();
        _scanner.CancelScan();
        IsScanning = false;
    }

    public void ToggleAdminConsole()
    {
        ShowAdminConsole = !ShowAdminConsole;
    }

    public void UpdateStatsFromIpc(DashboardStats stats)
    {
        Stats = stats;
        Status = stats.ThreatsBlocked > 0 ? ScanStatus.ThreatDetected : ScanStatus.Clean;
        UpdateVisualState(Status);
    }

    public void UpdateConnectionState(bool connected)
    {
        if (connected)
        {
            StatusText = "Connected to core agent";
            Status = ScanStatus.Idle;
        }
        else
        {
            StatusText = "Core agent offline — using simulation";
            Status = ScanStatus.Idle;
        }
        UpdateVisualState(Status);
    }

    public void UpdateIpcError(string error)
    {
        Status = ScanStatus.Error;
        StatusText = $"IPC error: {error}";
        UpdateVisualState(Status);
    }

    private void UpdateVisualState(ScanStatus status)
    {
        StatusColor = status switch
        {
            ScanStatus.Clean => new SolidColorBrush(Color.FromRgb(16, 185, 129)),
            ScanStatus.ThreatDetected => new SolidColorBrush(Color.FromRgb(239, 68, 68)),
            ScanStatus.Scanning => new SolidColorBrush(Color.FromRgb(250, 204, 21)),
            ScanStatus.Error => new SolidColorBrush(Color.FromRgb(249, 115, 22)),
            _ => new SolidColorBrush(Color.FromRgb(156, 163, 175)),
        };
        StatusGlyph = status switch
        {
            ScanStatus.Clean => "\uE734",
            ScanStatus.ThreatDetected => "\uE783",
            ScanStatus.Scanning => "\uE768",
            ScanStatus.Error => "\uE814",
            _ => "\uE734",
        };
    }

    private void OnProcessDiscovered(ProcessEntry entry)
    {
        App.Current.Dispatcher.Invoke(() =>
        {
            NewProcessEntry?.Invoke(entry);
        });
    }

    private void OnStatsUpdated(DashboardStats stats)
    {
        App.Current.Dispatcher.Invoke(() =>
        {
            Stats = stats;
        });
    }

    private void OnStatusChanged(ScanStatus status)
    {
        App.Current.Dispatcher.Invoke(() =>
        {
            Status = status;
            IsScanning = status == ScanStatus.Scanning;
            StatusColor = status switch
            {
                ScanStatus.Clean => new SolidColorBrush(Color.FromRgb(16, 185, 129)),
                ScanStatus.ThreatDetected => new SolidColorBrush(Color.FromRgb(239, 68, 68)),
                ScanStatus.Scanning => new SolidColorBrush(Color.FromRgb(250, 204, 21)),
                ScanStatus.Error => new SolidColorBrush(Color.FromRgb(249, 115, 22)),
                _ => new SolidColorBrush(Color.FromRgb(156, 163, 175)),
            };
            StatusText = status switch
            {
                ScanStatus.Clean => "SentryAVTT is protecting your PC",
                ScanStatus.ThreatDetected => "Threats detected — action required",
                ScanStatus.Scanning => "Scanning in progress...",
                ScanStatus.Error => "Scan encountered an error",
                _ => "SentryAVTT is ready",
            };
            StatusGlyph = status switch
            {
                ScanStatus.Clean => "\uE734",
                ScanStatus.ThreatDetected => "\uE783",
                ScanStatus.Scanning => "\uE768",
                ScanStatus.Error => "\uE814",
                _ => "\uE734",
            };
        });
    }

    private void OnScanError(string error)
    {
        App.Current.Dispatcher.Invoke(() =>
        {
            Status = ScanStatus.Error;
            StatusText = $"Error: {error}";
        });
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }
}
