using System.Windows;
using SentryAVTT.UI.Services;
using SentryAVTT.UI.ViewModels;

namespace SentryAVTT.UI;

public partial class App : Application
{
    public static ScanService Scanner { get; } = new();
    public static IpcService Ipc { get; } = new();
    public static DashboardViewModel Dashboard { get; } = new(Scanner);
    public static AdminConsoleViewModel AdminConsole { get; } = new();

    protected override void OnStartup(StartupEventArgs e)
    {
        Dashboard.NewProcessEntry += entry => AdminConsole.AddEntry(entry);

        // Wire IPC events to dashboard
        Ipc.StatsReceived += stats =>
        {
            Dispatcher.Invoke(() => Dashboard.UpdateStatsFromIpc(stats));
        };
        Ipc.ThreatDetected += entry =>
        {
            Dispatcher.Invoke(() => AdminConsole.AddEntry(entry));
        };
        Ipc.ConnectionStateChanged += connected =>
        {
            Dispatcher.Invoke(() => Dashboard.UpdateConnectionState(connected));
        };
        Ipc.ErrorOccurred += error =>
        {
            Dispatcher.Invoke(() => Dashboard.UpdateIpcError(error));
        };

        // Attempt to connect to Rust core agent
        _ = TryConnectIpcAsync();

        base.OnStartup(e);
    }

    private static async Task TryConnectIpcAsync()
    {
        try
        {
            await Ipc.ConnectAsync();
        }
        catch
        {
            // Core not running — UI works in offline/simulation mode
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Ipc.Disconnect();
        Scanner.Dispose();
        base.OnExit(e);
    }
}
