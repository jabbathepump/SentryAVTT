using System.IO;
using System.IO.Pipes;
using ProtoBuf;
using SentryAVTT.UI.Ipc;

namespace SentryAVTT.UI.Services;

/// <summary>
/// Low-level Named Pipe client that exchanges length-prefixed protobuf Envelopes
/// with the Rust core agent over \\.\pipe\SentryAVTT\main.
/// Wire format: [4-byte LE payload length] [protobuf-encoded Envelope].
/// </summary>
public sealed class PipeClient : IDisposable
{
    private NamedPipeClientStream? _pipe;
    private CancellationTokenSource? _readCts;
    private Task? _readLoop;
    private ulong _nextSeq;

    public event Action<Envelope>? MessageReceived;
    public event Action<string>? Disconnected;
    public event Action<string>? Error;

    public bool IsConnected => _pipe?.IsConnected ?? false;

    public async Task ConnectAsync(string pipeName = @"SentryAVTT\main", int timeoutMs = 5000)
    {
        try
        {
            _pipe = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.WriteThrough);

            await _pipe.ConnectAsync(timeoutMs);
            _readCts = new CancellationTokenSource();
            _readLoop = Task.Run(() => ReadLoopAsync(_readCts.Token));
        }
        catch (Exception ex)
        {
            Error?.Invoke($"Connection failed: {ex.Message}");
            throw;
        }
    }

    public async Task<Envelope> SendRequestAsync(Envelope request)
    {
        if (_pipe is not { IsConnected: true })
            throw new InvalidOperationException("Pipe not connected");

        request.Sequence = ++_nextSeq;
        request.TimestampMs = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await WriteEnvelopeAsync(request);

        return request;
    }

    public async Task SendEventAsync(Envelope envelope)
    {
        if (_pipe is not { IsConnected: true })
            return;

        envelope.TimestampMs = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        await WriteEnvelopeAsync(envelope);
    }

    public void Disconnect()
    {
        _readCts?.Cancel();
        _pipe?.Dispose();
        _pipe = null;
    }

    public void Dispose()
    {
        Disconnect();
        _readCts?.Dispose();
    }

    private async Task WriteEnvelopeAsync(Envelope envelope)
    {
        // Serialize Envelope to protobuf bytes
        using var ms = new MemoryStream();
        Serializer.Serialize(ms, envelope);
        var payload = ms.ToArray();

        // Write [4-byte LE length][payload]
        var lengthPrefix = BitConverter.GetBytes(payload.Length);
        if (!BitConverter.IsLittleEndian)
            Array.Reverse(lengthPrefix);

        await _pipe!.WriteAsync(lengthPrefix, 0, 4);
        await _pipe!.WriteAsync(payload, 0, payload.Length);
        await _pipe!.FlushAsync();
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        var lengthBuffer = new byte[4];

        while (!ct.IsCancellationRequested && _pipe?.IsConnected == true)
        {
            try
            {
                // Read 4-byte length prefix
                var bytesRead = 0;
                while (bytesRead < 4)
                {
                    var n = await _pipe!.ReadAsync(lengthBuffer, bytesRead, 4 - bytesRead, ct);
                    if (n == 0) throw new EndOfStreamException("Pipe closed");
                    bytesRead += n;
                }

                var payloadLength = BitConverter.ToUInt32(lengthBuffer, 0);

                // Read payload
                var payload = new byte[payloadLength];
                bytesRead = 0;
                while (bytesRead < payloadLength)
                {
                    var n = await _pipe!.ReadAsync(payload, bytesRead,
                        (int)(payloadLength - bytesRead), ct);
                    if (n == 0) throw new EndOfStreamException("Pipe closed");
                    bytesRead += n;
                }

                // Deserialize
                using var ms = new MemoryStream(payload);
                var envelope = Serializer.Deserialize<Envelope>(ms);
                MessageReceived?.Invoke(envelope);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (EndOfStreamException)
            {
                Disconnected?.Invoke("Pipe closed by server");
                break;
            }
            catch (Exception ex)
            {
                Error?.Invoke($"Read error: {ex.Message}");
                break;
            }
        }

        Disconnected?.Invoke("Read loop ended");
    }
}
