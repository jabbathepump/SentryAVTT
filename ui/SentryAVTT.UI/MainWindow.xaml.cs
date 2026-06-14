using System.Windows;
using System.Windows.Controls;
using SentryAVTT.UI.Models;
using SentryAVTT.UI.ViewModels;

namespace SentryAVTT.UI;

public partial class MainWindow : Window
{
    private readonly DashboardViewModel _dashboard;

    public MainWindow()
    {
        InitializeComponent();

        DataContext = App.Dashboard;
        _dashboard = App.Dashboard;

        // Wire up admin console data source
        ProcessLogGrid.ItemsSource = App.AdminConsole.ScanLog;

        // Subscribe to admin console visibility
        _dashboard.AdminConsoleVisibilityChanged += OnAdminConsoleVisibilityChanged;

        // Window dragging
        TitleBar.MouseLeftButtonDown += (s, e) => DragMove();
    }

    private async void ScanNow_Click(object sender, RoutedEventArgs e)
    {
        if (_dashboard.IsScanning)
        {
            _dashboard.CancelScan();
            return;
        }

        Button? btn = sender as Button;
        if (btn != null) btn.IsEnabled = false;

        await _dashboard.StartScanAsync();

        if (btn != null) btn.IsEnabled = true;
    }

    private void OpenQuarantine_Click(object sender, RoutedEventArgs e)
    {
        NavigateToPage("quarantine");
    }

    private void ClearLog_Click(object sender, RoutedEventArgs e)
    {
        App.AdminConsole.ClearLog();
    }

    private void ToggleAdmin_Click(object sender, RoutedEventArgs e)
    {
        _dashboard.ToggleAdminConsole();
    }

    private void DashboardNav_Click(object sender, RoutedEventArgs e)
    {
        NavigateToPage("dashboard");
    }

    private void QuarantineNav_Click(object sender, RoutedEventArgs e)
    {
        NavigateToPage("quarantine");
    }

    private void AboutNav_Click(object sender, RoutedEventArgs e)
    {
        NavigateToPage("about");
    }

    private void NavigateToPage(string page)
    {
        _dashboard.ShowAdminConsole = false;

        DashboardPage.Visibility = Visibility.Collapsed;
        QuarantinePage.Visibility = Visibility.Collapsed;
        AboutPage.Visibility = Visibility.Collapsed;

        switch (page)
        {
            case "dashboard":
                DashboardPage.Visibility = Visibility.Visible;
                break;
            case "quarantine":
                QuarantinePage.Visibility = Visibility.Visible;
                break;
            case "about":
                AboutPage.Visibility = Visibility.Visible;
                break;
        }
    }

    private void OnAdminConsoleVisibilityChanged(bool visible)
    {
        AdminConsolePanel.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
    }
}
