using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using Secbox.Sentinel.Contracts;

namespace Secbox.Sentinel.Engine.Collection;

// Owns the single TraceEventSession that backs the entire service. Hosts
// every registered IKernelProvider, multiplexes their normalized output
// into one bounded channel that downstream consumers (PipeServer fanout)
// pull from.
//
// CALLER MUST HAVE SeSystemProfilePrivilege (effectively requires Admin or
// the LocalSystem service identity). Construction throws otherwise — that's
// the wall between "user-mode tracing only" and "kernel providers".
//
// Lifecycle: ctor → AddProvider × N → StartAsync → consume Events channel
//   → DisposeAsync (also disposes the underlying session).
public sealed class EtwCollector : IAsyncDisposable, IKernelEventSink
{
    public const string SessionName = "SecboxSentinel/Kernel";

    readonly ILogger<EtwCollector> _log;
    readonly List<IKernelProvider> _providers = new();
    readonly Channel<KernelEvent> _channel = Channel.CreateBounded<KernelEvent>(
        new BoundedChannelOptions(capacity: 65_536)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = false,
            SingleWriter = false,
        });

    TraceEventSession? _session;
    Task? _processingTask;
    long _publishedSequence;
    long _droppedSinceStart;

    public EtwCollector(ILogger<EtwCollector> log)
    {
        _log = log;
    }

    public ChannelReader<KernelEvent> Events => _channel.Reader;
    public long PublishedSequence => Interlocked.Read(ref _publishedSequence);
    public long DroppedCount => Interlocked.Read(ref _droppedSinceStart);

    public void AddProvider(IKernelProvider provider)
    {
        if (_session != null) throw new InvalidOperationException("Cannot add providers after start.");
        _providers.Add(provider);
    }

    public Task StartAsync(CancellationToken ct)
    {
        if (_session != null) throw new InvalidOperationException("Already started.");

        // Stop any orphaned session left behind by a previous crashed run —
        // the Windows kernel session name is global, leaks across restarts.
        try
        {
            using var preexisting = new TraceEventSession(SessionName);
            preexisting.Stop(noThrow: true);
        }
        catch { /* best-effort cleanup */ }

        _session = new TraceEventSession(SessionName)
        {
            BufferSizeMB = 256,
            StopOnDispose = true,
        };

        var keywords = KernelTraceEventParser.Keywords.None;
        foreach (var p in _providers) keywords |= p.Keywords;

        if (keywords == KernelTraceEventParser.Keywords.None)
            throw new InvalidOperationException("No providers registered — nothing to collect.");

        _session.EnableKernelProvider(keywords, KernelTraceEventParser.Keywords.None);
        foreach (var p in _providers) p.Subscribe(_session.Source.Kernel, this);

        _log.LogInformation("ETW kernel session armed with keywords {Keywords}", keywords);

        // TraceEventSession.Source.Process() is BLOCKING — run it on its own
        // thread. It returns only when the session stops (StopOnDispose or
        // explicit Stop). All event callbacks fire on this thread.
        _processingTask = Task.Factory.StartNew(
            () =>
            {
                try { _session.Source.Process(); }
                catch (Exception ex) { _log.LogError(ex, "TraceEventSession.Process threw"); }
                finally { _channel.Writer.TryComplete(); }
            },
            ct,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);

        return Task.CompletedTask;
    }

    void IKernelEventSink.Publish(KernelEvent ev)
    {
        // Attach a monotonic sequence here so downstream subscribers can
        // detect drops without coordinating across channels.
        var seqd = ev with { Sequence = Interlocked.Increment(ref _publishedSequence) };
        if (!_channel.Writer.TryWrite(seqd))
            Interlocked.Increment(ref _droppedSinceStart);
    }

    public async ValueTask DisposeAsync()
    {
        try { _session?.Dispose(); } catch { }
        if (_processingTask != null) { try { await _processingTask.ConfigureAwait(false); } catch { } }
        _channel.Writer.TryComplete();
    }
}
