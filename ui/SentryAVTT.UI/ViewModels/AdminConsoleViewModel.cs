using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using SentryAVTT.UI.Models;

namespace SentryAVTT.UI.ViewModels;

public sealed class AdminConsoleViewModel : INotifyPropertyChanged
{
    private const int MaxLogEntries = 500;

    public ObservableCollection<ProcessEntry> ScanLog { get; } = new();

    public void AddEntry(ProcessEntry entry)
    {
        App.Current.Dispatcher.Invoke(() =>
        {
            ScanLog.Insert(0, entry);
            while (ScanLog.Count > MaxLogEntries)
                ScanLog.RemoveAt(ScanLog.Count - 1);
        });
    }

    public void ClearLog()
    {
        App.Current.Dispatcher.Invoke(() => ScanLog.Clear());
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
