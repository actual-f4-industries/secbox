using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Secbox.Sentinel.Contracts;

namespace Secbox.Sentinel.Client;

// Pipe client used by Secbox.Core's EtwSensor. Owns the connection, the
// hello/auth handshake, and the JSON line-protocol read loop. Surfaces
// KernelEvents as a Channel<KernelEvent> so the consumer (correlator) can
// pump on its own schedule without back-pressuring the read loop into the
// pipe transport.
//
// Threading model:
//   - One dedicated read task per connection, decoupled via Channel.
//   - Writes are awaited under a SemaphoreSlim — one writer at a time.
//   - All public methods are thread-safe.
//
// Lifecycle: Construct → ConnectAsync (idempotent) → SubscribeAsync (1..n)
//   → consume Events / Status changes → DisposeAsync.
public sealed class SentinelClient : IAsyncDisposable
{
    readonly string _pipeName;
    readonly int _editorPid;
    readonly string _clientBuild;
    readonly ReconnectPolicy _reconnect;

    NamedPipeClientStream? _pipe;
    StreamReader? _reader;
    StreamWriter? _writer;
    readonly SemaphoreSlim _writeLock = new(1, 1);
    CancellationTokenSource? _cts;
    Task? _readLoopTask;

    readonly Channel<KernelEvent> _events = Channel.CreateBounded<KernelEvent>(
        new BoundedChannelOptions(capacity: 16_384)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = false,
            SingleWriter = true,
        });

    public ChannelReader<KernelEvent> Events => _events.Reader;
    public ClientStatus Status { get; private set; } = ClientStatus.Disconnected;
    public string? LastError { get; private set; }
    public event Action<ClientStatus>? StatusChanged;

    public SentinelClient(int editorPid, string clientBuild, ReconnectPolicy? reconnect = null)
    {
        _editorPid = editorPid;
        _clientBuild = clientBuild;
        _reconnect = reconnect ?? new ReconnectPolicy();
        _pipeName = SentinelProtocol.PipeName;
    }

    public async Task ConnectAsync(CancellationToken ct = default)
    {
        if (Status == ClientStatus.Connected || Status == ClientStatus.Connecting) return;
        SetStatus(ClientStatus.Connecting);

        Exception? lastEx = null;
        while (!ct.IsCancellationRequested && _reconnect.ShouldRetry)
        {
            try
            {
                await ConnectOnceAsync(ct).ConfigureAwait(false);
                _reconnect.Reset();
                return;
            }
            catch (Exception ex)
            {
                lastEx = ex;
                LastError = ex.Message;
                if (!_reconnect.ShouldRetry) { SetStatus(ClientStatus.Failed); throw; }
                try { await Task.Delay(_reconnect.NextDelay(), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        SetStatus(ClientStatus.Failed);
        // Surface the actual underlying connect error. Without this, the
        // loop terminates via the WHILE condition (ShouldRetry=false) without
        // ever re-throwing, and the caller sees a misleading downstream
        // "Sentinel client not connected" from EnsureConnected() instead of
        // the real pipe/auth/handshake reason.
        if (lastEx != null) throw lastEx;
    }

    async Task ConnectOnceAsync(CancellationToken ct)
    {
        _pipe = new NamedPipeClientStream(
            serverName: ".",
            pipeName: _pipeName,
            direction: PipeDirection.InOut,
            options: PipeOptions.Asynchronous);

        await _pipe.ConnectAsync(timeout: 5000, ct).ConfigureAwait(false);

        _reader = new StreamReader(_pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        _writer = new StreamWriter(_pipe, new UTF8Encoding(false), bufferSize: 4096, leaveOpen: true) { AutoFlush = true };

        SetStatus(ClientStatus.Authenticating);
        var ack = await HandshakeAsync(ct).ConfigureAwait(false);
        if (!ack.Authenticated)
            throw new InvalidOperationException("Sentinel rejected hello (not authenticated).");
        if (ack.ServerProtocolVersion < SentinelProtocol.MinSupportedVersion
            || ack.ServerProtocolVersion > SentinelProtocol.CurrentVersion)
            throw new InvalidOperationException(
                $"Sentinel protocol skew. Client v{SentinelProtocol.CurrentVersion}, server v{ack.ServerProtocolVersion}.");

        _cts = new CancellationTokenSource();
        _readLoopTask = Task.Run(() => ReadLoopAsync(_cts.Token));
        SetStatus(ClientStatus.Connected);
    }

    async Task<HelloAck> HandshakeAsync(CancellationToken ct)
    {
        var nonce = Guid.NewGuid().ToString("N");
        await SendAsync(new EventEnvelope
        {
            Type = EventEnvelope.Types.Hello,
            Hello = new HelloRequest(SentinelProtocol.CurrentVersion, _clientBuild, _editorPid, nonce),
        }, ct).ConfigureAwait(false);

        var line = await _reader!.ReadLineAsync(ct).ConfigureAwait(false)
            ?? throw new IOException("Sentinel closed pipe during handshake.");
        var env = JsonSerializer.Deserialize<EventEnvelope>(line, EnvelopeJson.Options)
            ?? throw new IOException("Sentinel sent unparseable handshake reply.");

        if (env.Type == EventEnvelope.Types.Error && env.Error != null)
            throw new InvalidOperationException($"Sentinel error: {env.Error.Code} — {env.Error.Message}");
        if (env.Type != EventEnvelope.Types.HelloAck || env.HelloAck == null)
            throw new IOException($"Expected hello-ack, got {env.Type}");

        return env.HelloAck;
    }

    public async Task<SubscribeAck> SubscribeAsync(SubscribeRequest req, CancellationToken ct = default)
    {
        EnsureConnected();
        await SendAsync(new EventEnvelope
        {
            Type = EventEnvelope.Types.Subscribe,
            Subscribe = req,
        }, ct).ConfigureAwait(false);

        // Subscribe-ack is delivered via the read loop and forwarded through a
        // short-lived TaskCompletionSource keyed by SubscriptionId.
        //
        // 10s hard timeout — service-side issue (malformed JSON, pipe closed
        // mid-handshake, deserialiser dropping our envelope) must NEVER hang
        // the caller indefinitely. EtwSensor catches TimeoutException and
        // moves on with Status=Failed; the editor isn't stuck waiting forever.
        var tcs = new TaskCompletionSource<SubscribeAck>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingSubscribeAcks[req.SubscriptionId] = tcs;
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));
        using var reg = timeoutCts.Token.Register(() =>
            tcs.TrySetException(new TimeoutException(
                $"Sentinel did not send subscribe-ack for {req.SubscriptionId} within 10 seconds")));
        try { return await tcs.Task.ConfigureAwait(false); }
        finally { _pendingSubscribeAcks.TryRemove(req.SubscriptionId, out _); }
    }

    public Task UnsubscribeAsync(string subscriptionId, CancellationToken ct = default)
    {
        EnsureConnected();
        return SendAsync(new EventEnvelope
        {
            Type = EventEnvelope.Types.Unsubscribe,
            Unsubscribe = new UnsubscribeRequest(subscriptionId),
        }, ct);
    }

    readonly System.Collections.Concurrent.ConcurrentDictionary<string, TaskCompletionSource<SubscribeAck>>
        _pendingSubscribeAcks = new();

    async Task ReadLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var line = await _reader!.ReadLineAsync(ct).ConfigureAwait(false);
                if (line == null) break;
                if (line.Length == 0) continue;

                EventEnvelope? env;
                try { env = JsonSerializer.Deserialize<EventEnvelope>(line, EnvelopeJson.Options); }
                catch { continue; /* skip malformed lines, never tear down for a parser hiccup */ }
                if (env == null) continue;

                switch (env.Type)
                {
                    case EventEnvelope.Types.Event when env.Event != null:
                        // DropOldest on full channel — backpressure absorbed locally.
                        _events.Writer.TryWrite(env.Event);
                        break;

                    case EventEnvelope.Types.SubscribeAck when env.SubscribeAck != null:
                        if (_pendingSubscribeAcks.TryRemove(env.SubscribeAck.SubscriptionId, out var tcs))
                            tcs.TrySetResult(env.SubscribeAck);
                        break;

                    case EventEnvelope.Types.Backpressure:
                        // Surface via status — caller can monitor LastError.
                        if (env.Backpressure != null)
                            LastError = $"backpressure: {env.Backpressure.DroppedSinceLast} dropped (total {env.Backpressure.TotalDropped})";
                        break;

                    case EventEnvelope.Types.Error when env.Error != null:
                        LastError = $"{env.Error.Code}: {env.Error.Message}";
                        SetStatus(ClientStatus.Degraded);
                        break;

                    case EventEnvelope.Types.Pong:
                        // ignored for now; pong is just a liveness check
                        break;

                    // unknown types are silently dropped (forward-compat)
                }
            }
        }
        catch (OperationCanceledException) { /* shutdown */ }
        catch (Exception ex)
        {
            LastError = ex.Message;
        }
        finally
        {
            SetStatus(ClientStatus.Disconnected);
            _events.Writer.TryComplete();
            // Fail every pending subscribe-ack so callers don't await forever.
            // Without this, if the read loop dies (pipe closed, parse failure,
            // service crash) after a SubscribeRequest was sent, the caller's
            // TaskCompletionSource never completes and EtwSensor.StartAsync
            // hangs — which holds the adapter's _attachLock indefinitely and
            // blocks every subsequent Detach / ReapplySettings call.
            foreach (var kv in _pendingSubscribeAcks)
            {
                kv.Value.TrySetException(new IOException(
                    "Sentinel read loop ended before subscribe-ack arrived. " +
                    $"Last error: {LastError ?? "(unknown)"}"));
            }
            _pendingSubscribeAcks.Clear();
        }
    }

    async Task SendAsync(EventEnvelope env, CancellationToken ct)
    {
        if (_writer == null) throw new InvalidOperationException("Sentinel client not connected.");
        var json = JsonSerializer.Serialize(env, EnvelopeJson.Options);
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try { await _writer.WriteLineAsync(json.AsMemory(), ct).ConfigureAwait(false); }
        finally { _writeLock.Release(); }
    }

    void EnsureConnected()
    {
        if (Status != ClientStatus.Connected)
            throw new InvalidOperationException($"Sentinel client not connected (status={Status}).");
    }

    void SetStatus(ClientStatus s)
    {
        if (Status == s) return;
        Status = s;
        try { StatusChanged?.Invoke(s); } catch { }
    }

    public async ValueTask DisposeAsync()
    {
        try { _cts?.Cancel(); } catch { }
        try { if (_readLoopTask != null) await _readLoopTask.ConfigureAwait(false); } catch { }
        try { _writer?.Dispose(); } catch { }
        try { _reader?.Dispose(); } catch { }
        try { _pipe?.Dispose(); } catch { }
        _writeLock.Dispose();
        _events.Writer.TryComplete();
    }
}
