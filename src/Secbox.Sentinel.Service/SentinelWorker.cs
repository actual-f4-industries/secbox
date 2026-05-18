using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Secbox.Sentinel.Engine;
using Secbox.Sentinel.Engine.Policy;
using Secbox.Sentinel.Service.Pipe;

namespace Secbox.Sentinel.Service;

// Top-level BackgroundService. Starts the ETW collector, fans events out
// to every registered pipe client session, and runs the pipe-accept loop.
//
// One single loop owns the dispatch — keeps the cross-session ordering
// deterministic and avoids the cost of one thread per session for the
// (usually 1, occasionally 2-3) editors connected concurrently.
public sealed class SentinelWorker : BackgroundService
{
    readonly EngineHost _engine;
    readonly PipeServer _pipes;
    readonly ILogger<SentinelWorker> _log;

    public SentinelWorker(EngineHost engine, PipeServer pipes, ILogger<SentinelWorker> log)
    {
        _engine = engine;
        _pipes = pipes;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("Secbox Sentinel starting");

        try { await _engine.StartAsync(stoppingToken).ConfigureAwait(false); }
        catch (Exception ex)
        {
            _log.LogCritical(ex, "ETW kernel session failed to start — check service runs as SYSTEM/Admin");
            throw;
        }

        var pipeAccept = _pipes.RunAsync(stoppingToken);
        var dispatch = DispatchLoopAsync(stoppingToken);

        await Task.WhenAny(pipeAccept, dispatch).ConfigureAwait(false);
        _log.LogInformation("Secbox Sentinel stopping");
    }

    async Task DispatchLoopAsync(CancellationToken ct)
    {
        await foreach (var ev in _engine.Collector.Events.ReadAllAsync(ct).ConfigureAwait(false))
        {
            foreach (var sub in _engine.Subscriptions.Snapshot())
            {
                var match = _engine.Matcher.Match(ev, sub);
                if (!match.Forward) continue;
                _pipes.Forward(sub.SubscriptionId, ev);
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try { await _engine.DisposeAsync().ConfigureAwait(false); } catch { }
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }
}
