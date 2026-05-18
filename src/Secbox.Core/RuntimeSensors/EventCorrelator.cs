using System.Threading.Channels;
using Secbox.Contracts;
using Secbox.Core.RuntimeSensors.Sinks;

namespace Secbox.Core.RuntimeSensors;

// Single consumer of the per-sensor event channels. Per event:
//   1. Resolves a CallAttributionRing entry (if any).
//   2. Dedupes against the recent-events window — same (Tid, Kind, Target)
//      fired by another sensor within ±DedupeWindowMs accumulates a sensor
//      id rather than producing a second finding.
//   3. Routes the AttributedFinding to every registered IOutputSink.
//
// One correlator instance per process. Owned by the SensorRegistry.
public sealed class EventCorrelator : IAsyncDisposable
{
    public const int DedupeWindowMs = 75;

    readonly Channel<SensorEvent> _channel = Channel.CreateBounded<SensorEvent>(
        new BoundedChannelOptions(capacity: 32_768)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });

    readonly List<IOutputSink> _sinks = new();
    readonly Func<SensorEvent, CallAttributionRing.Entry?, Severity> _severityFn;
    readonly Dictionary<DedupeKey, AttributedFinding> _recent = new();
    long _sequence;
    Task? _runTask;
    CancellationTokenSource? _cts;

    public ChannelWriter<SensorEvent> Writer => _channel.Writer;

    public EventCorrelator(Func<SensorEvent, CallAttributionRing.Entry?, Severity>? severityFn = null)
    {
        _severityFn = severityFn ?? DefaultSeverity;
    }

    public void AddSink(IOutputSink sink) { lock (_sinks) _sinks.Add(sink); }

    public Task StartAsync(CancellationToken ct)
    {
        if (_runTask != null) return _runTask;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _runTask = Task.Run(() => RunLoopAsync(_cts.Token), _cts.Token);
        return Task.CompletedTask;
    }

    async Task RunLoopAsync(CancellationToken ct)
    {
        try
        {
            await foreach (var ev in _channel.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                ProcessOne(ev);
                if (_recent.Count > 4096) EvictRecent(ev.Timestamp);
            }
        }
        catch (OperationCanceledException) { }
    }

    void ProcessOne(SensorEvent ev)
    {
        var attribution = CallAttributionRing.Lookup(ev.Tid, ev.Tid, ev.Timestamp);
        var key = new DedupeKey(ev.Tid, ev.Kind, ev.Target);

        if (_recent.TryGetValue(key, out var existing) &&
            (ev.Timestamp - existing.Timestamp).Duration().TotalMilliseconds < DedupeWindowMs)
        {
            // Already emitted within window — accumulate sensor id and skip.
            if (!existing.SensorIds.Contains(ev.SensorId))
            {
                var merged = existing with { SensorIds = existing.SensorIds.Append(ev.SensorId).ToList() };
                _recent[key] = merged;
                EmitMergedAck(merged);
            }
            return;
        }

        var sev = _severityFn(ev, attribution);
        var seq = Interlocked.Increment(ref _sequence);
        var finding = new AttributedFinding(
            Sequence: seq,
            Timestamp: ev.Timestamp,
            Kind: ev.Kind,
            Severity: sev,
            SensorIds: new[] { ev.SensorId },
            Pid: ev.Pid,
            Tid: ev.Tid,
            Target: ev.Target,
            CallerAssembly: attribution?.CallerAssembly,
            CallerMethod: attribution?.CallerMethod,
            Note: attribution == null && IsManagedRelevantKernel(ev.Kind)
                ? "kernel-only — no managed attribution; likely native-trampoline or untracked call"
                : null,
            PayloadJson: ev.PayloadJson);

        _recent[key] = finding;
        EmitNew(finding);
    }

    void EmitNew(AttributedFinding f)
    {
        List<IOutputSink> sinks;
        lock (_sinks) sinks = _sinks.ToList();
        foreach (var s in sinks)
        {
            try { s.Emit(f); }
            catch { /* sink failures must not tear down the correlator */ }
        }
    }

    void EmitMergedAck(AttributedFinding f)
    {
        // Optional: sinks may want to know about sensor-id accumulation. Default
        // is silent — the consumer of EmitNew already counted the finding once.
        // Re-emit for sinks that opted in via IDedupeAwareOutputSink (future).
    }

    void EvictRecent(DateTimeOffset now)
    {
        var stale = _recent.Where(kv => (now - kv.Value.Timestamp).TotalSeconds > 5).Select(kv => kv.Key).ToList();
        foreach (var k in stale) _recent.Remove(k);
    }

    static bool IsManagedRelevantKernel(SensorEventKind k) => k switch
    {
        SensorEventKind.FileDelete or SensorEventKind.FileWrite
            or SensorEventKind.ProcessStart or SensorEventKind.NetTcpConnect => true,
        _ => false,
    };

    // Default severity heuristic. Pluggable via ctor.
    static Severity DefaultSeverity(SensorEvent ev, CallAttributionRing.Entry? a) => ev.Kind switch
    {
        SensorEventKind.FileDelete => Severity.High,
        SensorEventKind.ProcessStart => Severity.Critical,
        SensorEventKind.NetTcpConnect => Severity.Medium,
        SensorEventKind.DynamicMethodEmitted => Severity.Medium,
        SensorEventKind.RegSetValue or SensorEventKind.RegDeleteKey => Severity.Medium,
        _ => Severity.Low,
    };

    readonly record struct DedupeKey(int Tid, SensorEventKind Kind, string? Target);

    public async ValueTask DisposeAsync()
    {
        try { _cts?.Cancel(); } catch { }
        if (_runTask != null) { try { await _runTask.ConfigureAwait(false); } catch { } }
        _channel.Writer.TryComplete();
        List<IOutputSink> sinks;
        lock (_sinks) sinks = _sinks.ToList();
        foreach (var s in sinks)
        {
            try { await s.DisposeAsync().ConfigureAwait(false); } catch { }
        }
    }
}
