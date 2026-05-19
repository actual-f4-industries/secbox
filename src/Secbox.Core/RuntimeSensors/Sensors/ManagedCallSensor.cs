using System.Diagnostics;
using System.IO;
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
    static EnforcementPolicy _policy = new();
    // Diagnostic counter — total times the Process.Start prefix has run
    // since attach. Read by tests / status panels to confirm patching
    // actually took effect (Harmony is meant to be invisible, but when
    // attribution misses for an expected library spawn we need to know
    // whether the prefix even ran). Reset on StopAsync.
    static long _prefixHits;
    public static long PrefixHits => Interlocked.Read(ref _prefixHits);
    Harmony? _harmony;

    public Task StartAsync(SensorOptions options, ChannelWriter<SensorEvent> sink, CancellationToken ct)
    {
        Status = SensorStatus.Starting;
        try
        {
            _sink = sink;
            _policy = options.Enforcement ?? new EnforcementPolicy();
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
        _policy = new EnforcementPolicy();
        Interlocked.Exchange(ref _prefixHits, 0);
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

    // Prefix / Postfix bodies — private-static is what Harmony reflects to.
    // Signature follows Harmony's named-parameter convention:
    //   __state    — prefix-to-postfix data passing
    //   __result   — patched method's return value (ref to override)
    //   __instance — `this` for instance methods
    //
    // Prefix return value: `bool` — returning false skips the original
    // method entirely (the patched method does NOT run; __result is what
    // the caller sees instead). True lets the original execute normally.
    //
    // Enforcement flow:
    //   1. Walk stack — is caller a library? If not, return true (allow).
    //   2. Record attribution into CallAttributionRing for downstream
    //      correlator joins.
    //   3. If _policy.BlockLibraryProcessStart: emit blocked event,
    //      set __result to null/false, return false → original skipped.
    //   4. Otherwise stash attribution in __state for the postfix to emit
    //      a ManagedProcessStart event after the spawn succeeds.
    static bool StaticStartPrefix(out object? __state, ref Process? __result)
    {
        __state = null;
        try
        {
            Interlocked.Increment(ref _prefixHits);
            var lib = AttributeToLibrary();
            if (lib == null) return true;

            RecordAttribution(lib);

            if (_policy.BlockLibraryProcessStart)
            {
                __result = null;
                EmitBlocked(lib);
                return false;
            }

            __state = lib;
            return true;
        }
        catch
        {
            __state = null;
            return true;
        }
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

    static bool InstanceStartPrefix(out object? __state, ref bool __result)
    {
        __state = null;
        try
        {
            Interlocked.Increment(ref _prefixHits);
            var lib = AttributeToLibrary();
            if (lib == null) return true;

            RecordAttribution(lib);

            if (_policy.BlockLibraryProcessStart)
            {
                __result = false;
                EmitBlocked(lib);
                return false;
            }

            __state = lib;
            return true;
        }
        catch
        {
            __state = null;
            return true;
        }
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
    // declaring assembly is plausibly library code. Returns null when the
    // caller is the editor / engine / BCL — non-library calls intentionally
    // pass through (the editor makes plenty of internal Process.Start calls).
    //
    // Side-effect-free: callers decide whether to record attribution / emit.
    static LibraryAttribution? AttributeToLibrary()
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
            if (!IsLibraryAttributable(asm, asmName, path)) continue;

            return new LibraryAttribution
            {
                AssemblyName = asmName,
                MethodName = method != null
                    ? $"{method.DeclaringType?.FullName}.{method.Name}"
                    : "(unknown)",
                AssemblyPath = path,
            };
        }
        return null;
    }

    // Write into the CallAttributionRing so a subsequent kernel ProcessStart
    // event for the spawned child can be joined with library attribution.
    // Keyed by (managed thread id, native thread id) — kernel events carry
    // the native tid, so the correlator's nativeTid scan finds us.
    static void RecordAttribution(LibraryAttribution lib)
    {
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
    }

    // Emit a Critical-severity finding indicating the library's spawn was
    // refused. Sequenced through the same channel as other events — sinks
    // pick it up and surface in Recent Findings.
    //
    // Also drops a JSON file in %PROGRAMDATA%\secbox\alerts\ — the service's
    // AlertSpawner watches that directory and launches SecboxAlertUI.exe in
    // the active user's session. Doing the file drop SYNCHRONOUSLY here (in
    // the prefix, before we return false to skip the original Process.Start)
    // guarantees the alert payload is on disk before library code can pause
    // or deadlock the editor. The service is in its own process; even if
    // the editor freezes, AlertSpawner picks up the file and shows the UI.
    static void EmitBlocked(LibraryAttribution lib)
    {
        var nowIso = DateTimeOffset.UtcNow.ToString("O");
        var payload = JsonSerializer.Serialize(new
        {
            severity = "Critical",
            kind = "BlockedManagedProcessStart",
            target = $"{lib.AssemblyName}!{lib.MethodName}",
            callerAssembly = lib.AssemblyName,
            callerMethod = lib.MethodName,
            timestamp = nowIso,
            pid = Environment.ProcessId,
            action = "Blocked",
            note = "Library-attributed Process.Start was refused by Tier E EnforcementPolicy. "
                 + "The original Process.Start did not execute; calling library code will see a "
                 + "null return value and may throw on the next member access.",
        });

        TryDropAlertFile(payload);

        _sink?.TryWrite(new SensorEvent(
            Sequence: Interlocked.Increment(ref _sequence),
            SensorId: "managed-call",
            Kind: SensorEventKind.BlockedManagedProcessStart,
            Timestamp: DateTimeOffset.UtcNow,
            Pid: Environment.ProcessId,
            Tid: Environment.CurrentManagedThreadId,
            Target: $"{lib.AssemblyName}!{lib.MethodName}",
            PayloadJson: payload));
    }

    // Drop folder: %PROGRAMDATA%\secbox\alerts\. Pre-create attempts during
    // attach; here we re-create defensively in case the dir was wiped.
    static readonly string AlertDropFolder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "secbox", "alerts");

    static void TryDropAlertFile(string payloadJson)
    {
        try
        {
            Directory.CreateDirectory(AlertDropFolder);
            // Write to a .tmp first then rename so AlertSpawner's
            // FileSystemWatcher never sees a partially-written file.
            var name = $"{DateTime.UtcNow:yyyyMMddTHHmmssfff}_{Guid.NewGuid():N}.json";
            var tmp = Path.Combine(AlertDropFolder, name + ".tmp");
            var final = Path.Combine(AlertDropFolder, name);
            File.WriteAllText(tmp, payloadJson);
            File.Move(tmp, final);
        }
        catch { /* swallow — alert UI is best-effort; the SensorEvent path
                  through the channel/correlator is the durable record */ }
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

    // A frame is "library-attributable" when ANY of these match:
    //
    //   1. The assembly's AssemblyLoadContext is an IsolatedAssemblyContext
    //      — s&box loads each downloaded package into its own
    //      collectible ALC named "IsolatedAssemblyContext" (see
    //      Sandbox.Reflection/TypeLibrary/LoadContext.cs:15). MOST RELIABLE
    //      signal because it survives in-memory loads, custom AssemblyName,
    //      and non-canonical paths.
    //   2. The assembly name carries s&box's runtime-compiler `package.`
    //      prefix (Compiler.cs:98 in sbox-public). Catches packages loaded
    //      via the runtime compiler path.
    //   3. The assembly was loaded from a library directory on disk
    //      (`\Libraries\` source tree or `\.bin\` compiled output). Catches
    //      libraries loaded from files when ALC and naming don't match.
    static bool IsLibraryAttributable(Assembly asm, string asmName, string? path)
    {
        try
        {
            var alc = System.Runtime.Loader.AssemblyLoadContext.GetLoadContext(asm);
            // Library packages live in IsolatedAssemblyContext (per-package
            // collectible). Engine code lives in the default ALC ("") or
            // s&box's shared TLC. Tier B (profiler) sees the same boundary.
            if (alc != null && alc.Name == "IsolatedAssemblyContext") return true;
        }
        catch { /* GetLoadContext can throw on dynamic / collectible quirks */ }

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
