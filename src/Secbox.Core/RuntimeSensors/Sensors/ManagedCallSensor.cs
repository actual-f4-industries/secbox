using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Channels;
using HarmonyLib;

namespace Secbox.Core.RuntimeSensors.Sensors;

// Tier E sensor — managed-call tripwires installed via Harmony runtime
// patches. Intercepts `System.Diagnostics.Process.Start` and similar APIs
// in the editor process so library-originated calls are attributed before
// the resulting kernel event (Tier A) lands.
//
// Per call:
//   1. Prefix walks the managed stack to find the highest non-system,
//      non-secbox frame. If that frame's assembly is a library (loaded
//      from `\Libraries\` or `\.bin\`, OR name starts with `package.`),
//      record an entry in CallAttributionRing keyed by current thread.
//   2. Postfix reads the resulting Process (PID + image path) and emits
//      a SensorEvent of ManagedProcessStart kind so the spawn appears as
//      an attributed finding even if Tier A (ETW) is disabled.
//
// When Tier A IS enabled, the kernel ProcessStart event arrives milliseconds
// later. The EventCorrelator does Lookup(managedTid, nativeTid, …) against
// our ring entry and joins library attribution onto the kernel finding —
// "package.scfu spawned process Z (image scfu.exe)" rather than just
// "editor descendant spawned Z."
//
// Safety:
//   * Every patch body wrapped in try/catch — a throw from a Harmony patch
//     propagates into the patched method and would crash the editor.
//   * Stack walks use System.Diagnostics.StackTrace (managed-frame iteration
//     only; cheap when fNeedFileInfo=false).
//   * Patching is idempotent within a sensor lifetime; StopAsync unpatches.
public sealed class ManagedCallSensor : ISensor
{
    public string Id => "managed-call";
    public SensorCapabilities Capabilities => SensorCapabilities.ManagedCalls;

    public SensorStatus Status { get; private set; } = SensorStatus.Disabled;
    public string? LastError { get; private set; }

    const string HarmonyId = "secbox.managed-call";

    static ChannelWriter<SensorEvent>? _sink;
    static long _sequence;
    Harmony? _harmony;

    public Task StartAsync(SensorOptions options, ChannelWriter<SensorEvent> sink, CancellationToken ct)
    {
        Status = SensorStatus.Starting;
        try
        {
            _sink = sink;
            _harmony = new Harmony(HarmonyId);
            PatchProcessStart(_harmony);
            Status = SensorStatus.Healthy;
        }
        catch (Exception ex)
        {
            LastError = $"{ex.GetType().Name}: {ex.Message}";
            Status = SensorStatus.Failed;
        }
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken ct)
    {
        try { _harmony?.UnpatchAll(HarmonyId); } catch { }
        _harmony = null;
        _sink = null;
        Status = SensorStatus.Disabled;
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync() => new(StopAsync(CancellationToken.None));

    static void PatchProcessStart(Harmony h)
    {
        var staticPrefix = new HarmonyMethod(typeof(ManagedCallSensor)
            .GetMethod(nameof(StaticStartPrefix), BindingFlags.NonPublic | BindingFlags.Static)!);
        var staticPostfix = new HarmonyMethod(typeof(ManagedCallSensor)
            .GetMethod(nameof(StaticStartPostfix), BindingFlags.NonPublic | BindingFlags.Static)!);
        var instancePrefix = new HarmonyMethod(typeof(ManagedCallSensor)
            .GetMethod(nameof(InstanceStartPrefix), BindingFlags.NonPublic | BindingFlags.Static)!);
        var instancePostfix = new HarmonyMethod(typeof(ManagedCallSensor)
            .GetMethod(nameof(InstanceStartPostfix), BindingFlags.NonPublic | BindingFlags.Static)!);

        // Static Process.Start overloads — there are ~5 of them; the one
        // SCFU calls is Process.Start(ProcessStartInfo).
        var staticStarts = typeof(Process)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(m => m.Name == "Start" && m.ReturnType == typeof(Process));
        foreach (var m in staticStarts)
        {
            try { h.Patch(m, prefix: staticPrefix, postfix: staticPostfix); }
            catch { /* per-overload — one failure shouldn't lose the rest */ }
        }

        // Instance Process.Start() — invoked after `new Process { StartInfo = … }`.
        // Returns bool. Postfix reads __instance.Id to get the spawned PID.
        var instanceStart = typeof(Process)
            .GetMethod("Start", BindingFlags.Public | BindingFlags.Instance, Type.EmptyTypes);
        if (instanceStart != null)
        {
            try { h.Patch(instanceStart, prefix: instancePrefix, postfix: instancePostfix); }
            catch { }
        }
    }

    // Prefix / Postfix bodies — public-static-or-private-static is what
    // Harmony reflects to. Signature follows Harmony's named-parameter
    // convention: `__state` for prefix-to-postfix data passing, `__result`
    // for the patched method's return value, `__instance` for `this`.
    static void StaticStartPrefix(out object? __state)
    {
        __state = null;
        try { __state = RecordIfLibraryCaller(); }
        catch { __state = null; }
    }

    static void StaticStartPostfix(object? __state, Process? __result)
    {
        try
        {
            if (__state is not LibraryAttribution lib || __result == null) return;
            EmitSpawn(lib, __result);
        }
        catch { }
    }

    static void InstanceStartPrefix(out object? __state)
    {
        __state = null;
        try { __state = RecordIfLibraryCaller(); }
        catch { __state = null; }
    }

    static void InstanceStartPostfix(object? __state, Process __instance, bool __result)
    {
        try
        {
            if (!__result || __state is not LibraryAttribution lib) return;
            EmitSpawn(lib, __instance);
        }
        catch { }
    }

    // Walk the managed stack outwards looking for the first frame whose
    // declaring assembly is plausibly library code. If found, record an
    // attribution entry and return it so the postfix can also emit a
    // SensorEvent. Returns null when the caller is the editor / engine /
    // BCL — non-library calls are intentionally not surfaced (the editor
    // makes lots of internal Process.Start calls).
    static LibraryAttribution? RecordIfLibraryCaller()
    {
        var st = new StackTrace(skipFrames: 2, fNeedFileInfo: false);
        for (int i = 0; i < st.FrameCount; i++)
        {
            var frame = st.GetFrame(i);
            var method = frame?.GetMethod();
            var asm = method?.DeclaringType?.Assembly;
            if (asm == null) continue;

            var asmName = asm.GetName().Name ?? "";
            if (IsInternalAssembly(asmName)) continue;

            var path = TryGetAssemblyLocation(asm);
            if (!IsLibraryAttributable(asmName, path)) continue;

            var lib = new LibraryAttribution
            {
                AssemblyName = asmName,
                MethodName = method != null
                    ? $"{method.DeclaringType?.FullName}.{method.Name}"
                    : "(unknown)",
                AssemblyPath = path,
            };

            CallAttributionRing.Record(new CallAttributionRing.Entry
            {
                TimestampTicks = DateTimeOffset.UtcNow.UtcTicks,
                ManagedTid = Environment.CurrentManagedThreadId,
                NativeTid = (int)GetCurrentThreadId(),
                CallerAssembly = lib.AssemblyName,
                CallerMethod = lib.MethodName,
                Op = "Process.Start",
                ArgsSummary = null,
            });

            return lib;
        }
        return null;
    }

    static void EmitSpawn(LibraryAttribution lib, Process p)
    {
        int pid;
        string? image;
        try { pid = p.Id; } catch { pid = 0; }
        try { image = p.StartInfo?.FileName; } catch { image = null; }

        var payload = JsonSerializer.Serialize(new
        {
            library = lib.AssemblyName,
            method = lib.MethodName,
            childPid = pid,
            image,
        });

        _sink?.TryWrite(new SensorEvent(
            Sequence: Interlocked.Increment(ref _sequence),
            SensorId: "managed-call",
            Kind: SensorEventKind.ManagedProcessStart,
            Timestamp: DateTimeOffset.UtcNow,
            Pid: pid,
            Tid: Environment.CurrentManagedThreadId,
            Target: image,
            PayloadJson: payload));
    }

    // Internal = our own assemblies + Harmony + BCL. These aren't the
    // library boundary — keep walking outwards.
    static bool IsInternalAssembly(string name) =>
        name.Length == 0
        || name.StartsWith("Secbox.", StringComparison.OrdinalIgnoreCase)
        || name.Equals("0Harmony", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("HarmonyLib", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("MonoMod", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("System.", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("netstandard", StringComparison.OrdinalIgnoreCase)
        || name.Equals("mscorlib", StringComparison.OrdinalIgnoreCase);

    // A frame is "library-attributable" when the assembly was loaded from a
    // library directory the editor scans (`\Libraries\` source or `\.bin\`
    // compiled output) OR the assembly name carries s&box's `package.`
    // prefix (see Compiler.cs:98 in sbox-public).
    static bool IsLibraryAttributable(string asmName, string? path)
    {
        if (asmName.StartsWith("package.", StringComparison.OrdinalIgnoreCase)) return true;
        if (string.IsNullOrEmpty(path)) return false;
        return path.IndexOf(@"\Libraries\", StringComparison.OrdinalIgnoreCase) >= 0
            || path.IndexOf(@"\.bin\", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    static string? TryGetAssemblyLocation(Assembly asm)
    {
        try
        {
            // Assembly.Location returns "" for in-memory loads (which is what
            // s&box does for remote packages — see CompileCodeArchive's use
            // of memoryFileSystem). When empty, fall back to CodeBase / null.
            var loc = asm.Location;
            return string.IsNullOrEmpty(loc) ? null : loc;
        }
        catch { return null; }
    }

    [DllImport("kernel32", EntryPoint = "GetCurrentThreadId")]
    static extern uint GetCurrentThreadId();

    sealed class LibraryAttribution
    {
        public required string AssemblyName { get; init; }
        public required string MethodName { get; init; }
        public string? AssemblyPath { get; init; }
    }
}
