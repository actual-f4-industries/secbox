using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Secbox.Sentinel.Contracts;
using Secbox.Sentinel.Engine;
using Secbox.Sentinel.Engine.Policy;

namespace Secbox.Sentinel.Service.Pipe;

// One per connected client. Owns the pipe stream, the per-client outbound
// queue, and the set of subscriptions the client owns. Subscriptions are
// torn down automatically when the session ends — no leaked entries in the
// SubscriptionRegistry across reconnects.
internal sealed class PipeClientSession
{
    readonly int _id;
    readonly NamedPipeServerStream _pipe;
    readonly EngineHost _engine;
    readonly ClientAuthenticator _auth;
    readonly Action<string, PipeClientSession> _onSubAdded;
    readonly Action<string> _onSubRemoved;
    readonly ILogger<PipeClientSession> _log;

    readonly TaskCompletionSource _complete = new(TaskCreationOptions.RunContinuationsAsynchronously);
    readonly Channel<EventEnvelope> _out = Channel.CreateBounded<EventEnvelope>(
        new BoundedChannelOptions(capacity: 8_192) { FullMode = BoundedChannelFullMode.DropOldest });

    long _droppedSinceLast;
    long _totalDropped;
    AuthResult _authResult;
    readonly HashSet<string> _mySubscriptions = new();

    public Task WhenComplete => _complete.Task;

    public PipeClientSession(
        int id,
        NamedPipeServerStream pipe,
        EngineHost engine,
        ClientAuthenticator auth,
        Action<string, PipeClientSession> onSubscriptionAdded,
        Action<string> onSubscriptionRemoved,
        ILogger<PipeClientSession> log)
    {
        _id = id;
        _pipe = pipe;
        _engine = engine;
        _auth = auth;
        _onSubAdded = onSubscriptionAdded;
        _onSubRemoved = onSubscriptionRemoved;
        _log = log;
    }

    public void Enqueue(KernelEvent ev)
    {
        var env = new EventEnvelope { Type = EventEnvelope.Types.Event, Event = ev };
        if (!_out.Writer.TryWrite(env))
        {
            Interlocked.Increment(ref _droppedSinceLast);
            Interlocked.Increment(ref _totalDropped);
        }
    }

    public async Task RunAsync(CancellationToken ct)
    {
        StreamReader? reader = null;
        StreamWriter? writer = null;
        Task? sendLoop = null;

        try
        {
            reader = new StreamReader(_pipe, Encoding.UTF8, false, leaveOpen: true);
            writer = new StreamWriter(_pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };

            // Hello + auth.
            var helloLine = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (helloLine == null) return;
            var helloEnv = TryParse(helloLine);
            if (helloEnv?.Hello == null)
            {
                await SendErrorAsync(writer, ErrorCodes.ProtocolMismatch, "missing or malformed hello", ct);
                return;
            }

            _authResult = _auth.Authenticate(_pipe, helloEnv.Hello.EditorPid);
            var ack = new HelloAck(
                ServerProtocolVersion: SentinelProtocol.CurrentVersion,
                ServerBuild: typeof(PipeClientSession).Assembly.GetName().Version?.ToString() ?? "0.0",
                Challenge: Guid.NewGuid().ToString("N"),
                Authenticated: _authResult.Ok);
            await SendAsync(writer, new EventEnvelope { Type = EventEnvelope.Types.HelloAck, HelloAck = ack }, ct);

            if (!_authResult.Ok)
            {
                _log.LogWarning("session {Id}: auth denied: {Reason}", _id, _authResult.Reason);
                return;
            }
            _log.LogInformation("session {Id}: authenticated pid={Pid} image={Image}",
                _id, _authResult.CallerPid, _authResult.ImagePath);

            sendLoop = SendLoopAsync(writer, ct);
            await ReadLoopAsync(reader, writer, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* shutting down */ }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "session {Id}: error", _id);
        }
        finally
        {
            _out.Writer.TryComplete();
            try { if (sendLoop != null) await sendLoop.ConfigureAwait(false); } catch { }
            foreach (var sid in _mySubscriptions.ToList())
            {
                _engine.Subscriptions.Remove(sid);
                _onSubRemoved(sid);
            }
            try { reader?.Dispose(); } catch { }
            try { writer?.Dispose(); } catch { }
            try { _pipe.Dispose(); } catch { }
            _complete.TrySetResult();
        }
    }

    async Task ReadLoopAsync(StreamReader reader, StreamWriter writer, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (line == null) return;
            if (line.Length == 0) continue;

            var env = TryParse(line);
            if (env == null) continue;

            switch (env.Type)
            {
                case EventEnvelope.Types.Subscribe when env.Subscribe != null:
                    await HandleSubscribeAsync(env.Subscribe, writer, ct);
                    break;
                case EventEnvelope.Types.Unsubscribe when env.Unsubscribe != null:
                    HandleUnsubscribe(env.Unsubscribe);
                    break;
                case EventEnvelope.Types.Ping when env.Ping != null:
                    await SendAsync(writer, new EventEnvelope
                    {
                        Type = EventEnvelope.Types.Pong,
                        Pong = new PongMessage(DateTimeOffset.UtcNow),
                    }, ct);
                    break;
                // unknown types silently dropped
            }
        }
    }

    async Task HandleSubscribeAsync(SubscribeRequest req, StreamWriter writer, CancellationToken ct)
    {
        var sub = Subscription.From(req, _authResult.CallerPid);
        if (!_engine.Subscriptions.TryAdd(sub))
        {
            await SendAsync(writer, new EventEnvelope
            {
                Type = EventEnvelope.Types.SubscribeAck,
                SubscribeAck = new SubscribeAck(req.SubscriptionId, ProviderKind.None,
                    RejectionReason: "subscription limit reached"),
            }, ct);
            return;
        }

        _mySubscriptions.Add(req.SubscriptionId);
        _onSubAdded(req.SubscriptionId, this);

        await SendAsync(writer, new EventEnvelope
        {
            Type = EventEnvelope.Types.SubscribeAck,
            SubscribeAck = new SubscribeAck(req.SubscriptionId, req.Providers),
        }, ct);
    }

    void HandleUnsubscribe(UnsubscribeRequest req)
    {
        if (_mySubscriptions.Remove(req.SubscriptionId))
        {
            _engine.Subscriptions.Remove(req.SubscriptionId);
            _onSubRemoved(req.SubscriptionId);
        }
    }

    async Task SendLoopAsync(StreamWriter writer, CancellationToken ct)
    {
        try
        {
            await foreach (var env in _out.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                await SendAsync(writer, env, ct).ConfigureAwait(false);

                // Periodic backpressure summary — every 256 events check counters.
                if ((env.Event?.Sequence ?? 0) % 256 == 0)
                {
                    var dropped = Interlocked.Exchange(ref _droppedSinceLast, 0);
                    if (dropped > 0)
                    {
                        await SendAsync(writer, new EventEnvelope
                        {
                            Type = EventEnvelope.Types.Backpressure,
                            Backpressure = new BackpressureNotice("*", dropped, Interlocked.Read(ref _totalDropped)),
                        }, ct).ConfigureAwait(false);
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogWarning(ex, "session {Id}: send loop ended", _id); }
    }

    static async Task SendAsync(StreamWriter writer, EventEnvelope env, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(env, EnvelopeJson.Options);
        await writer.WriteLineAsync(json.AsMemory(), ct).ConfigureAwait(false);
    }

    static async Task SendErrorAsync(StreamWriter writer, string code, string message, CancellationToken ct) =>
        await SendAsync(writer, new EventEnvelope
        {
            Type = EventEnvelope.Types.Error,
            Error = new ErrorMessage(code, message),
        }, ct).ConfigureAwait(false);

    static EventEnvelope? TryParse(string line)
    {
        try { return JsonSerializer.Deserialize<EventEnvelope>(line, EnvelopeJson.Options); }
        catch { return null; }
    }
}
