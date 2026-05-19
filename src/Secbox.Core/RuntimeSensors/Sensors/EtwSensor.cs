using System.Threading.Channels;
using Secbox.Sentinel.Client;
using Secbox.Sentinel.Contracts;

namespace Secbox.Core.RuntimeSensors.Sensors;

// Tier A sensor — connects to the Sentinel service, subscribes for the
// editor's PID, translates KernelEvents into SensorEvents. Connection
// failures move Status to Degraded/Failed rather than throwing.
public sealed class EtwSensor : ISensor
{
    public string Id => "etw";
    public SensorCapabilities Capabilities =>
        SensorCapabilities.KernelFile | SensorCapabilities.KernelProcess
        | SensorCapabilities.KernelNetwork | SensorCapabilities.KernelRegistry
        | SensorCapabilities.NativeImageLoad;

    public SensorStatus Status { get; private set; } = SensorStatus.Disabled;
    public string? LastError { get; private set; }

    SentinelClient? _client;
    Task? _pumpTask;
    CancellationTokenSource? _cts;
    long _sequence;

    public async Task StartAsync(SensorOptions options, ChannelWriter<SensorEvent> sink, CancellationToken ct)
    {
        Status = SensorStatus.Starting;
        try
        {
            // Bounded reconnect — Tier A is non-critical, must NEVER hang the
            // editor when the Sentinel pipe is unreachable. Default policy
            // retries indefinitely with exponential backoff, which holds the
            // adapter's _attachLock forever and breaks Detach/ReapplySettings.
            // 3 attempts × ~5s each = ~16 seconds worst case before we
            // surface Status=Failed and let the editor proceed.
            var reconnect = new Sentinel.Client.ReconnectPolicy
            {
                InitialDelay = TimeSpan.FromMilliseconds(100),
                MaxDelay = TimeSpan.FromSeconds(1),
                MaxAttempts = 3,
            };
            _client = new SentinelClient(
                editorPid: options.EditorPid,
                clientBuild: typeof(EtwSensor).Assembly.GetName().Version?.ToString() ?? "0.0.0",
                reconnect: reconnect);
            await _client.ConnectAsync(ct).ConfigureAwait(false);

            var providers = MapCapabilitiesToProviders(options.Desired);
            var sub = await _client.SubscribeAsync(new SubscribeRequest(
                SubscriptionId: Guid.NewGuid().ToString("N"),
                Providers: providers,
                CaptureStack: options.CaptureStack,
                MaxEventsPerSec: 5000,
                PathAllowlist: options.PathAllowlist), ct).ConfigureAwait(false);

            if (sub.GrantedProviders == ProviderKind.None)
            {
                Status = SensorStatus.Failed;
                LastError = sub.RejectionReason ?? "subscription denied";
                await _client.DisposeAsync();
                _client = null;
                return;
            }

            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _pumpTask = Task.Run(() => PumpAsync(sink, _cts.Token));
            Status = SensorStatus.Healthy;
        }
        catch (TimeoutException ex)
        {
            LastError = $"sentinel service not reachable: {ex.Message}";
            Status = SensorStatus.Failed;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Status = SensorStatus.Failed;
        }
    }

    static ProviderKind MapCapabilitiesToProviders(SensorCapabilities caps)
    {
        var p = ProviderKind.None;
        if ((caps & SensorCapabilities.KernelFile) != 0) p |= ProviderKind.File;
        if ((caps & SensorCapabilities.KernelProcess) != 0) p |= ProviderKind.Process;
        if ((caps & SensorCapabilities.KernelNetwork) != 0) p |= ProviderKind.Network;
        if ((caps & SensorCapabilities.KernelRegistry) != 0) p |= ProviderKind.Registry;
        if ((caps & SensorCapabilities.NativeImageLoad) != 0) p |= ProviderKind.ImageLoad;
        return p == ProviderKind.None ? ProviderKind.All : p;
    }

    async Task PumpAsync(ChannelWriter<SensorEvent> sink, CancellationToken ct)
    {
        if (_client == null) return;
        try
        {
            await foreach (var k in _client.Events.ReadAllAsync(ct).ConfigureAwait(false))
            {
                sink.TryWrite(Translate(k));
            }
        }
        catch (OperationCanceledException) { }
    }

    SensorEvent Translate(KernelEvent k) => new(
        Sequence: Interlocked.Increment(ref _sequence),
        SensorId: "etw",
        Kind: MapKind(k.Kind),
        Timestamp: k.Timestamp,
        Pid: k.Pid,
        Tid: k.Tid,
        Target: k.Path ?? k.Target,
        PayloadJson: null);

    static SensorEventKind MapKind(KernelEventKind k) => k switch
    {
        KernelEventKind.FileCreate => SensorEventKind.FileCreate,
        KernelEventKind.FileWrite => SensorEventKind.FileWrite,
        KernelEventKind.FileDelete => SensorEventKind.FileDelete,
        KernelEventKind.FileRename => SensorEventKind.FileRename,
        KernelEventKind.FileSetSecurity => SensorEventKind.FileSetSecurity,
        KernelEventKind.ProcessStart => SensorEventKind.ProcessStart,
        KernelEventKind.ProcessStop => SensorEventKind.ProcessStop,
        KernelEventKind.ImageLoad => SensorEventKind.NativeImageLoad,
        KernelEventKind.NetTcpConnect => SensorEventKind.NetTcpConnect,
        KernelEventKind.NetTcpSend => SensorEventKind.NetTcpSend,
        KernelEventKind.NetTcpRecv => SensorEventKind.NetTcpRecv,
        KernelEventKind.NetUdpSend => SensorEventKind.NetUdpSend,
        KernelEventKind.NetUdpRecv => SensorEventKind.NetUdpRecv,
        KernelEventKind.RegOpenKey => SensorEventKind.RegOpenKey,
        KernelEventKind.RegSetValue => SensorEventKind.RegSetValue,
        KernelEventKind.RegDeleteKey => SensorEventKind.RegDeleteKey,
        KernelEventKind.RegDeleteValue => SensorEventKind.RegDeleteValue,
        _ => SensorEventKind.Unknown,
    };

    public async Task StopAsync(CancellationToken ct)
    {
        try { _cts?.Cancel(); } catch { }
        if (_pumpTask != null) { try { await _pumpTask.ConfigureAwait(false); } catch { } }
        if (_client != null) { try { await _client.DisposeAsync().ConfigureAwait(false); } catch { } }
        _client = null;
        Status = SensorStatus.Disabled;
    }

    public ValueTask DisposeAsync() => new(StopAsync(CancellationToken.None));
}
