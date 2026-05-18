using System.Threading.Channels;

namespace Secbox.Core.RuntimeSensors;

// Unifying contract for every runtime-monitoring tier (Tier B profiler, Tier
// A ETW sidecar, future Tier D EventPipe, future Tier E Harmony). Sensors
// push normalized SensorEvents into a shared channel; the EventCorrelator is
// the single consumer that attributes and routes.
//
// Sensor implementations live under RuntimeSensors/Sensors/ and are
// registered into SensorRegistry. Adding a new tier = new ISensor class +
// one line in SensorRegistry.BuildDefault.
public interface ISensor : IAsyncDisposable
{
    string Id { get; }                           // "profiler", "etw", ...
    SensorCapabilities Capabilities { get; }
    SensorStatus Status { get; }
    string? LastError { get; }

    Task StartAsync(SensorOptions options, ChannelWriter<SensorEvent> sink, CancellationToken ct);
    Task StopAsync(CancellationToken ct);
}

[Flags]
public enum SensorCapabilities
{
    None = 0,
    ManagedCalls = 1 << 0,
    DynamicCode = 1 << 1,
    KernelFile = 1 << 2,
    KernelProcess = 1 << 3,
    KernelNetwork = 1 << 4,
    KernelRegistry = 1 << 5,
    NativeImageLoad = 1 << 6,
}

public enum SensorStatus
{
    Disabled,
    Starting,
    Healthy,
    Degraded,
    Failed,
}

public sealed record SensorOptions(
    int EditorPid,
    SensorCapabilities Desired,
    IReadOnlyList<string>? PathAllowlist = null,
    bool CaptureStack = false);
