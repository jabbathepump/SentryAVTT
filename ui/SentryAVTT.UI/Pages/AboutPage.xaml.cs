using System.Windows.Controls;
using SentryAVTT.UI.Ipc;

namespace SentryAVTT.UI.Pages;

public partial class AboutPage : UserControl
{
    public AboutPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, System.Windows.RoutedEventArgs e)
    {
        var stats = App.Dashboard.Stats;
        VersionText.Text = stats.Version;
        VersionDetailText.Text = stats.Version;
        SignatureText.Text = stats.SignatureAge;

        OsText.Text = Environment.OSVersion.ToString();
        ArchText.Text = Environment.Is64BitOperatingSystem ? "Yes" : "No";

        if (App.Ipc.IsConnected)
            CoreStatusText.Text = "Online — Connected";
        else
            CoreStatusText.Text = "Offline — Simulation Mode";
    }
}
