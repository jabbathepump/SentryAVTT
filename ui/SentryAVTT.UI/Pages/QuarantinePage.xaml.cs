using System.Windows;
using System.Windows.Controls;
using SentryAVTT.UI.ViewModels;

namespace SentryAVTT.UI.Pages;

public partial class QuarantinePage : UserControl
{
    private QuarantineViewModel? _vm;

    public QuarantinePage()
    {
        InitializeComponent();
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_vm != null) return;
        _vm = new QuarantineViewModel(App.Ipc);
        QuarantineGrid.DataContext = _vm;
        _ = _vm.LoadAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        if (_vm != null)
            await _vm.LoadAsync();
    }

    private async void Restore_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { CommandParameter: string id } && _vm != null)
            await _vm.RestoreAsync(id);
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { CommandParameter: string id } && _vm != null)
        {
            var result = MessageBox.Show(
                "Permanently delete this quarantined file?\nThis cannot be undone.",
                "Confirm Delete",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (result == MessageBoxResult.Yes)
                await _vm.DeleteAsync(id);
        }
    }
}
