using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Secbox.Sentinel.Contracts;
using Secbox.Sentinel.Engine;

namespace Secbox.Sentinel.Service.Pipe;

// Accepts pipe connections, spawns one PipeClientSession per connection,
// and provides the per-subscription forwarding hook that the dispatcher
// loop calls.
//
// Pipe DACL: read+write granted to the interactive user (well-known SID
// S-1-5-4) and to the local SYSTEM the service runs as. No remote, no
// other users. Service-side ACL is the first line of defence; the per-
// connection ClientAuthenticator is the second.
public sealed class PipeServer
{
    readonly EngineHost _engine;
    readonly ClientAuthenticator _auth;
    readonly ILoggerFactory _loggers;
    readonly ILogger<PipeServer> _log;

    readonly ConcurrentDictionary<string, PipeClientSession> _bySubscription = new();
    readonly ConcurrentDictionary<int, PipeClientSession> _byId = new();
    int _nextId;

    public PipeServer(EngineHost engine, ClientAuthenticator auth, ILoggerFactory loggers, ILogger<PipeServer> log)
    {
        _engine = engine;
        _auth = auth;
        _loggers = loggers;
        _log = log;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var pipeName = SentinelProtocol.PipeName;
        _log.LogInformation("Pipe server listening on {Pipe}", pipeName);

        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreatePipe(pipeName);
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);

                var id = Interlocked.Increment(ref _nextId);
                var session = new PipeClientSession(
                    id, pipe, _engine, _auth,
                    onSubscriptionAdded: (subId, s) => _bySubscription[subId] = s,
                    onSubscriptionRemoved: subId => _bySubscription.TryRemove(subId, out _),
                    _loggers.CreateLogger<PipeClientSession>());

                _byId[id] = session;
                // Rename the discard lambda param to avoid shadowing the
                // `out _` discard the compiler tries to bind to TryRemove.
                session.WhenComplete.ContinueWith(t => { _byId.TryRemove(id, out _); }, ct);

                _ = session.RunAsync(ct);
                pipe = null; // ownership transferred to session
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogError(ex, "PipeServer accept loop error");
                try { pipe?.Dispose(); } catch { }
                // Avoid tight loop on persistent failure.
                try { await Task.Delay(500, ct).ConfigureAwait(false); } catch { break; }
            }
        }
    }

    // Called by dispatcher loop for every event/subscription pair the matcher
    // approved. Routes to the session that owns that subscription. The session
    // applies its own per-pipe backpressure.
    public void Forward(string subscriptionId, KernelEvent ev)
    {
        if (_bySubscription.TryGetValue(subscriptionId, out var s))
            s.Enqueue(ev);
    }

    static NamedPipeServerStream CreatePipe(string pipeName)
    {
        var sec = new PipeSecurity();
        // SYSTEM (the service identity).
        sec.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        // Authenticated interactive user — fine-grained per-process auth still
        // happens in ClientAuthenticator.
        sec.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: NamedPipeServerStream.MaxAllowedServerInstances,
            transmissionMode: PipeTransmissionMode.Byte,
            options: PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            inBufferSize: 64 * 1024,
            outBufferSize: 1024 * 1024,
            pipeSecurity: sec);
    }
}
