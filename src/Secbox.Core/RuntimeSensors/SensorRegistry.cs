namespace Secbox.Core.RuntimeSensors;

// Owns the set of registered sensors and the shared EventCorrelator. The
// SecboxApi bridge layer talks to the registry; sensors don't need to know
// about each other.
public sealed class SensorRegistry : IAsyncDisposable
{
    readonly List<ISensor> _sensors = new();
    public EventCorrelator Correlator { get; }

    public SensorRegistry(EventCorrelator? correlator = null)
    {
        Correlator = correlator ?? new EventCorrelator();
    }

    public void Add(ISensor sensor)
    {
        lock (_sensors) _sensors.Add(sensor);
    }

    public IReadOnlyList<ISensor> Sensors
    {
        get { lock (_sensors) return _sensors.ToList(); }
    }

    public async Task StartAllAsync(SensorOptions opts, CancellationToken ct)
    {
        await Correlator.StartAsync(ct).ConfigureAwait(false);
        List<ISensor> snap;
        lock (_sensors) snap = _sensors.ToList();
        foreach (var s in snap)
        {
            try { await s.StartAsync(opts, Correlator.Writer, ct).ConfigureAwait(false); }
            catch { /* fail-soft per sensor — Status reflects the outcome */ }
        }
    }

    public async Task StopAllAsync(CancellationToken ct)
    {
        List<ISensor> snap;
        lock (_sensors) snap = _sensors.ToList();
        foreach (var s in snap)
        {
            try { await s.StopAsync(ct).ConfigureAwait(false); } catch { }
        }
    }

    public async ValueTask DisposeAsync()
    {
        List<ISensor> snap;
        lock (_sensors) snap = _sensors.ToList();
        foreach (var s in snap)
        {
            try { await s.DisposeAsync().ConfigureAwait(false); } catch { }
        }
        await Correlator.DisposeAsync().ConfigureAwait(false);
    }
}
