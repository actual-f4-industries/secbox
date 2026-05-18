using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Channels;
using Secbox.Core.Profiler;

namespace Secbox.Core.RuntimeSensors.Sensors;

// Tier B sensor — wraps the native Secbox.Profiler. Responsible for:
//   1. Telling ProfilerCoordinator to extract + attach the profiler DLL.
//   2. Registering the managed callback via P/Invoke.
//   3. Translating the native JSON payloads into SensorEvents on the
//      registry channel.
//
// The native callback fires on whatever runtime thread triggered the event
// (load thread, JIT thread, exception thread). We do bounded work in the
// callback: parse, build a SensorEvent, TryWrite to the channel. No
// blocking, no allocation beyond the event itself.
public sealed class ProfilerSensor : ISensor
{
    public string Id => "profiler";
    public SensorCapabilities Capabilities =>
        SensorCapabilities.ManagedCalls | SensorCapabilities.DynamicCode | SensorCapabilities.NativeImageLoad;

    public SensorStatus Status { get; private set; } = SensorStatus.Disabled;
    public string? LastError { get; private set; }

    static ChannelWriter<SensorEvent>? _sink;
    static long _sequence;

    public async Task StartAsync(SensorOptions options, ChannelWriter<SensorEvent> sink, CancellationToken ct)
    {
        Status = SensorStatus.Starting;
        try
        {
            await ProfilerCoordinator.EnsureAttachedAsync(ct).ConfigureAwait(false);
            _sink = sink;
            unsafe
            {
                Secbox_RegisterCallback((nint)(delegate* unmanaged[Stdcall]<int, char*, void>)&NativeCallback);
            }
            Secbox_DrainRing(); // catch up on events fired before our callback registered
            Status = SensorStatus.Healthy;
        }
        catch (DllNotFoundException ex)
        {
            LastError = $"profiler DLL not loadable: {ex.Message}";
            Status = SensorStatus.Failed;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Status = SensorStatus.Failed;
        }
    }

    public Task StopAsync(CancellationToken ct)
    {
        try { Secbox_RegisterCallback(0); } catch { }
        _sink = null;
        Status = SensorStatus.Disabled;
        return Task.CompletedTask;
    }

    // P/Invoke surface — the native DLL is loaded by ProfilerCoordinator
    // before this gets called.
    [DllImport(ProfilerCoordinator.NativeLibName, CallingConvention = CallingConvention.StdCall)]
    static extern void Secbox_RegisterCallback(nint callback);

    [DllImport(ProfilerCoordinator.NativeLibName, CallingConvention = CallingConvention.StdCall)]
    static extern int Secbox_GetStatus();

    [DllImport(ProfilerCoordinator.NativeLibName, CallingConvention = CallingConvention.StdCall)]
    static extern void Secbox_DrainRing();

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvStdcall) })]
    static unsafe void NativeCallback(int kind, char* payloadJson)
    {
        try
        {
            if (_sink == null) return;
            var payload = new string(payloadJson);
            var ev = BuildEvent(kind, payload);
            _sink.TryWrite(ev);
        }
        catch { /* exception across native callback boundary is undefined — swallow */ }
    }

    static SensorEvent BuildEvent(int nativeKind, string payloadJson)
    {
        var kind = MapKind(nativeKind);
        string? target = TryExtractStringField(payloadJson, kind switch
        {
            SensorEventKind.AssemblyLoaded => "name",
            SensorEventKind.ModuleLoaded => "path",
            _ => "name",
        });
        return new SensorEvent(
            Sequence: Interlocked.Increment(ref _sequence),
            SensorId: "profiler",
            Kind: kind,
            Timestamp: DateTimeOffset.UtcNow,
            Pid: Environment.ProcessId,
            Tid: Environment.CurrentManagedThreadId,
            Target: target,
            PayloadJson: payloadJson);
    }

    static SensorEventKind MapKind(int k) => k switch
    {
        1000 => SensorEventKind.AssemblyLoaded,
        1001 => SensorEventKind.ModuleLoaded,
        1002 => SensorEventKind.MethodJitted,
        1003 => SensorEventKind.DynamicMethodEmitted,
        1004 => SensorEventKind.ExceptionThrown,
        9000 or 9001 => SensorEventKind.ProfilerAttached,
        _ => SensorEventKind.Unknown,
    };

    static string? TryExtractStringField(string json, string field)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty(field, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString()
                : null;
        }
        catch { return null; }
    }

    public ValueTask DisposeAsync()
    {
        try { Secbox_RegisterCallback(0); } catch { }
        return ValueTask.CompletedTask;
    }
}
