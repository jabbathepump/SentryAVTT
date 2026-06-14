using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using SentryAVTT.UI.Ipc;
using SentryAVTT.UI.Services;

namespace SentryAVTT.UI.ViewModels;

public sealed class QuarantineViewModel : INotifyPropertyChanged
{
    private readonly IpcService _ipc;

    public ObservableCollection<QuarantineEntry> Entries { get; } = new();
    public bool IsConnected => _ipc.IsConnected;

    public QuarantineViewModel(IpcService ipc)
    {
        _ipc = ipc;
        _ipc.QuarantineListReceived += OnQuarantineListReceived;
        _ipc.QuarantineListReceived += _ =>
        {
            System.Windows.Application.Current.Dispatcher.Invoke(OnPropertyChanged);
        };
    }

    public async Task LoadAsync()
    {
        if (_ipc.IsConnected)
            await _ipc.RequestQuarantineListAsync();
    }

    public async Task RestoreAsync(string id)
    {
        if (!_ipc.IsConnected) return;
        await _ipc.RequestQuarantineRestoreAsync(id);
        await LoadAsync();
    }

    public async Task DeleteAsync(string id)
    {
        if (!_ipc.IsConnected) return;
        await _ipc.RequestQuarantineDeleteAsync(id);
        await LoadAsync();
    }

    private void OnQuarantineListReceived(List<QuarantineEntry> entries)
    {
        System.Windows.Application.Current.Dispatcher.Invoke(() =>
        {
            Entries.Clear();
            foreach (var e in entries)
                Entries.Add(e);
        });
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
