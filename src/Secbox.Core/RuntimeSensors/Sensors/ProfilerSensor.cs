using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Channels;
using Secbox.Core.Profiler;

namespace Secbox.Core.RuntimeSensors.Sensors;

// Tier B sensor — wraps the native Secbox.Profiler. Responsible for:
//   1. Telling ProfilerCoordinator to attach the native profiler.
//   2. Registering the managed callback via the explicit function pointer
//      ProfilerCoordinator exposes (NOT via [DllImport] / P/Invoke — see
//      ProfilerCoordinator block comment for why).
//   3. Translating native JSON payloads into SensorEvents on the registry
//      channel.
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

    // Native signature: void STDMETHODCALLTYPE (*)(int kind, const wchar_t* payload)
    unsafe delegate* unmanaged[Stdcall]<int, char*, void> NativeCallbackPtr =>
        &NativeCallback;

    // Native signature: void STDMETHODCALLTYPE Secbox_RegisterCallback(void* cb)
    unsafe delegate* unmanaged[Stdcall]<nint, void> RegisterCallbackThunk =>
        (delegate* unmanaged[Stdcall]<nint, void>)ProfilerCoordinator.RegisterCallbackFn;

    // Native signature: void STDMETHODCALLTYPE Secbox_DrainRing()
    unsafe delegate* unmanaged[Stdcall]<void> DrainRingThunk =>
        (delegate* unmanaged[Stdcall]<void>)ProfilerCoordinator.DrainRingFn;

    static ChannelWriter<SensorEvent>? _sink;
    static long _sequence;

    public async Task StartAsync(SensorOptions options, ChannelWriter<SensorEvent> sink, CancellationToken ct)
    {
        Status = SensorStatus.Starting;
        try
        {
            await ProfilerCoordinator.EnsureAttachedAsync(ct).ConfigureAwait(false);

            if (ProfilerCoordinator.RegisterCallbackFn == IntPtr.Zero)
            {
                LastError = "Profiler attached but Secbox_RegisterCallback export not bound.";
                Status = SensorStatus.Failed;
                return;
            }

            _sink = sink;

            unsafe
            {
                var cb = (nint)NativeCallbackPtr;
                RegisterCallbackThunk(cb);
                if (ProfilerCoordinator.DrainRingFn != IntPtr.Zero)
                    DrainRingThunk();
            }

            Status = SensorStatus.Healthy;
        }
        catch (Exception ex)
        {
            LastError = $"{ex.GetType().Name}: {ex.Message}";
            Status = SensorStatus.Failed;
        }
    }

    public Task StopAsync(CancellationToken ct)
    {
        try
        {
            unsafe
            {
                if (ProfilerCoordinator.RegisterCallbackFn != IntPtr.Zero)
                    RegisterCallbackThunk(IntPtr.Zero);   // unregister
            }
        }
        catch { }
        _sink = null;
        Status = SensorStatus.Disabled;
        return Task.CompletedTask;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
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
        try
        {
            unsafe
            {
                if (ProfilerCoordinator.RegisterCallbackFn != IntPtr.Zero)
                    RegisterCallbackThunk(IntPtr.Zero);
            }
        }
        catch { }
        return ValueTask.CompletedTask;
    }
}
