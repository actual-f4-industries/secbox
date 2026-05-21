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
    static ManagedCallTrustStore _trust = new();
    // Diagnostic counter — total times the Process.Start prefix has run
    // since attach. Read by tests / status panels to confirm patching
    // actually took effect (Harmony is meant to be invisible, but when
    // attribution misses for an expected library spawn we need to know
    // whether the prefix even ran). Reset on StopAsync.
    static long _prefixHits;
    public static long PrefixHits => Interlocked.Read(ref _prefixHits);
    // Re-entrancy guard for the suspend launch. SuspendAndDecide starts
    // SecboxAlertUI.exe with Process.Start — the very method we patch. The
    // library that triggered the suspend is still on this thread's stack, so
    // without this flag the launch re-enters the prefix, re-attributes to that
    // library, and calls SuspendAndDecide again → unbounded recursion →
    // StackOverflow (uncatchable; kills the editor). Set only for the duration
    // of our own launch; the nested prefix sees it and passes straight through.
    // Thread-static: a suspend on one thread must not blind other threads.
    [ThreadStatic] static bool _suspending;
    Harmony? _harmony;

    public Task StartAsync(SensorOptions options, ChannelWriter<SensorEvent> sink, CancellationToken ct)
    {
        Status = SensorStatus.Starting;
        try
        {
            _sink = sink;
            _policy = options.Enforcement ?? new EnforcementPolicy();
            _trust = ManagedCallTrustStore.Load();
            // Finish any library deletions deferred by a previous "Kill & remove
            // library" decision. The editor that requested them has since exited
            // (that decision Environment.Exit'd it), so the file locks that
            // blocked the immediate delete are now gone.
            CompletePendingRemovals();
            Trace("──────── ATTACH ────────");
            Trace($"StartAsync: Secbox.Core at '{SafeAsmLocation()}' (dev-drop path = dev mode active)");
            Trace($"StartAsync: BlockLibraryProcessStart={_policy.BlockLibraryProcessStart}, editorPid={Environment.ProcessId}");
            Trace($"StartAsync: ResolveAlertUiPath='{ResolveAlertUiPath() ?? "(NOT FOUND next to Core.dll)"}'");
            // s&box ships its OWN Mono.Cecil in the Default ALC, a different
            // version than MonoMod expects. MonoMod's Cecil-backed IL generator
            // binds to it and fails to load ("CecilILGenerator … violates the
            // constraint of TTarget"), killing all patching. Force MonoMod's
            // DynamicMethod (Reflection.Emit) backend, which uses no Cecil. Must
            // be set before the first MonoMod use — it caches the choice at init.
            Environment.SetEnvironmentVariable("MONOMOD_DMD_TYPE", "DynamicMethod");
            Trace($"StartAsync: MONOMOD_DMD_TYPE set to '{Environment.GetEnvironmentVariable("MONOMOD_DMD_TYPE")}' (force Reflection.Emit; avoid s&box Cecil)");
            EnsureHarmonyLoadable(); // MUST precede `new Harmony` — see method comment
            _harmony = new Harmony(HarmonyId);
            PatchProcessStart(_harmony);
            Status = SensorStatus.Healthy;
            Trace("StartAsync: status=Healthy");
        }
        catch (Exception ex)
        {
            LastError = $"{ex.GetType().Name}: {ex.Message}";
            Status = SensorStatus.Failed;
            Trace($"StartAsync: FAILED — {ex}");
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
        int staticPatched = 0;
        foreach (var m in staticStarts)
        {
            try { h.Patch(m, prefix: staticPrefix, postfix: staticPostfix); staticPatched++; }
            catch (Exception ex) { Trace($"PatchProcessStart: static overload patch failed — {ex.Message}"); }
        }
        Trace($"PatchProcessStart: patched {staticPatched} static Process.Start overload(s)");

        // Instance Process.Start() — invoked after `new Process { StartInfo = … }`.
        // Returns bool. Postfix reads __instance.Id to get the spawned PID.
        var instanceStart = typeof(Process)
            .GetMethod("Start", BindingFlags.Public | BindingFlags.Instance, Type.EmptyTypes);
        if (instanceStart != null)
        {
            try { h.Patch(instanceStart, prefix: instancePrefix, postfix: instancePostfix); Trace("PatchProcessStart: patched instance Process.Start()"); }
            catch (Exception ex) { Trace($"PatchProcessStart: instance patch failed — {ex.Message}"); }
        }
        else Trace("PatchProcessStart: instance Process.Start() NOT FOUND");
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
        if (_suspending) { Trace("StaticStartPrefix: re-entrant (our own AlertUI launch) → pass through"); return true; }
        try
        {
            Interlocked.Increment(ref _prefixHits);
            var lib = AttributeToLibrary();
            Trace($"StaticStartPrefix: hit#{PrefixHits} attributed={(lib?.AssemblyName ?? "(none — not a library frame)")}");
            if (lib == null) return true;

            RecordAttribution(lib);

            if (_policy.BlockLibraryProcessStart)
            {
                if (_trust.IsTrusted(lib.AssemblyName))
                {
                    // Previously trusted via "Allow & Trust" — skip prompt.
                    Trace($"  trusted → allow without prompt: {lib.AssemblyName}");
                    __state = lib;
                    return true;
                }

                Trace($"  enforce ON → SuspendAndDecide: {lib.AssemblyName}!{lib.MethodName}");
                var decision = SuspendAndDecide(lib);
                Trace($"  SuspendAndDecide returned {decision} (0=Block 1=Allow 2=Trust 3=Kill 4=Kill+Remove)");
                if (ApplyDecision(decision, lib))
                {
                    __state = lib;
                    return true; // user chose Allow — original runs
                }
                __result = null;
                return false; // Block / Kill (kill already exited)
            }

            Trace("  enforce OFF (BlockLibraryProcessStart=false) → observe-only, allow");
            __state = lib;
            return true;
        }
        catch (Exception ex)
        {
            Trace($"StaticStartPrefix: EX {ex.GetType().Name}: {ex.Message}");
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
        if (_suspending) { Trace("InstanceStartPrefix: re-entrant (our own AlertUI launch) → pass through"); return true; }
        try
        {
            Interlocked.Increment(ref _prefixHits);
            var lib = AttributeToLibrary();
            Trace($"InstanceStartPrefix: hit#{PrefixHits} attributed={(lib?.AssemblyName ?? "(none — not a library frame)")}");
            if (lib == null) return true;

            RecordAttribution(lib);

            if (_policy.BlockLibraryProcessStart)
            {
                if (_trust.IsTrusted(lib.AssemblyName))
                {
                    Trace($"  trusted → allow without prompt: {lib.AssemblyName}");
                    __state = lib;
                    return true;
                }

                Trace($"  enforce ON → SuspendAndDecide: {lib.AssemblyName}!{lib.MethodName}");
                var decision = SuspendAndDecide(lib);
                Trace($"  SuspendAndDecide returned {decision} (0=Block 1=Allow 2=Trust 3=Kill 4=Kill+Remove)");
                if (ApplyDecision(decision, lib))
                {
                    __state = lib;
                    return true;
                }
                __result = false;
                return false;
            }

            Trace("  enforce OFF (BlockLibraryProcessStart=false) → observe-only, allow");
            __state = lib;
            return true;
        }
        catch (Exception ex)
        {
            Trace($"InstanceStartPrefix: EX {ex.GetType().Name}: {ex.Message}");
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
        var rejected = new List<string>(); // debug: non-internal frames that failed the library test
        for (int i = 0; i < st.FrameCount; i++)
        {
            var frame = st.GetFrame(i);
            var method = frame?.GetMethod();
            var asm = method?.DeclaringType?.Assembly;
            if (asm == null) continue;

            var asmName = asm.GetName().Name ?? "";
            if (IsInternalAssembly(asmName)) continue;

            var path = TryGetAssemblyLocation(asm);
            if (!IsLibraryAttributable(asm, asmName, path))
            {
                rejected.Add($"{asmName}[alc={SafeAlcName(asm)};path={path ?? "(empty/in-memory)"}]");
                continue;
            }

            return new LibraryAttribution
            {
                AssemblyName = asmName,
                MethodName = method != null
                    ? $"{method.DeclaringType?.FullName}.{method.Name}"
                    : "(unknown)",
                AssemblyPath = path,
            };
        }
        // No library frame matched. Dump the non-internal candidates we DID see
        // so an attribution miss is diagnosable (wrong ALC name? path not under
        // \Libraries\ or \.bin\? name missing the package. prefix?).
        if (rejected.Count > 0)
            Trace($"AttributeToLibrary: no match; non-internal frames considered: {string.Join(" | ", rejected)}");
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

    // Decision codes returned by SecboxAlertUI as its exit code. Mirror
    // of Secbox.Sentinel.AlertUI.AlertDecision — kept in sync manually
    // because the projects don't share a reference.
    static class Decision
    {
        public const int Block         = 0;
        public const int Allow         = 1;
        public const int AllowAndTrust = 2;
        public const int Kill          = 3;
        public const int KillAndRemove = 4;
    }

    // Synchronously launch AlertUI with the suspension payload and wait
    // up to 10 minutes for the user's exit code. The library's calling
    // thread is blocked inside this method — that IS the suspension.
    // Library code cannot proceed past Process.Start until we return.
    //
    // 10 minute timeout: if the user goes AFK or AlertUI hangs, we fall
    // back to Block (safest). Block is also the exit code AlertUI emits
    // when the user closes the window without clicking a button.
    static int SuspendAndDecide(LibraryAttribution lib)
    {
        // 1. Emit the SensorEvent for audit (channel/correlator/log).
        EmitSuspended(lib);

        // 2. Write the payload to a PRIVATE temp path and pass it directly to
        //    the child we launch + wait on below. It must NOT go into the
        //    AlertSpawner drop folder (%PROGRAMDATA%\secbox\alerts): that
        //    folder is watched by the service, which would launch a SECOND,
        //    fire-and-forget AlertUI whose exit code is discarded — and which
        //    races this child to read+delete the single payload file, leaving
        //    the loser to abort with "payload missing" (exit 1 == Allow).
        var payloadPath = WriteSuspendPayload(lib);
        if (payloadPath == null) { Trace("SuspendAndDecide: WriteSuspendPayload FAILED → Block"); return Decision.Block; }
        Trace($"SuspendAndDecide: payload at '{payloadPath}'");

        // 3. Resolve AlertUI exe — same folder as this assembly.
        var exe = ResolveAlertUiPath();
        if (string.IsNullOrEmpty(exe))
        {
            Trace("SuspendAndDecide: AlertUI exe NOT FOUND next to Core.dll → Block");
            TryCleanupPayload(payloadPath);
            return Decision.Block;
        }
        Trace($"SuspendAndDecide: launching '{exe}' and waiting (up to 10 min)…");

        // 4. Synchronous launch + wait.
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false,
                CreateNoWindow = false,
                WorkingDirectory = Path.GetDirectoryName(exe),
            };
            psi.ArgumentList.Add(payloadPath);

            // Guard ONLY the launch: this Process.Start is the re-entrant call
            // into our own patch. WaitForExit below is not Process.Start, so it
            // doesn't need the flag — and we want the flag cleared while we
            // block for up to 10 minutes (other library spawns on OTHER threads
            // must still be intercepted normally).
            Process? p;
            _suspending = true;
            try { p = Process.Start(psi); }
            finally { _suspending = false; }
            if (p == null) { Trace("SuspendAndDecide: Process.Start returned null → Block"); return Decision.Block; }
            Trace($"SuspendAndDecide: AlertUI pid={SafePid(p)} started; waiting for exit…");

            using (p)
            {
                // Block the calling thread until AlertUI exits — that block IS
                // the suspension — capped at 10 min. We POLL HasExited rather
                // than trust WaitForExit(int): on the cold first launch of the
                // self-contained single-file exe, WaitForExit(600000) was seen
                // returning false within ~16 ms (before the dialog even renders),
                // which wrongly fell through to Block and handed the caller a
                // null/unstarted process. HasExited reads the real kernel state.
                var deadline = DateTime.UtcNow + TimeSpan.FromMinutes(10);
                while (true)
                {
                    bool exited;
                    try { exited = p.HasExited; }
                    catch { exited = true; } // handle gone — treat as exited
                    if (exited) break;
                    if (DateTime.UtcNow >= deadline)
                    {
                        Trace("SuspendAndDecide: 10-min cap reached → kill + Block");
                        try { p.Kill(entireProcessTree: true); } catch { }
                        return Decision.Block;
                    }
                    Thread.Sleep(150);
                }
                Trace($"SuspendAndDecide: AlertUI exited with code {p.ExitCode}");
                return p.ExitCode;
            }
        }
        catch (Exception ex)
        {
            Trace($"SuspendAndDecide: launch EX {ex.GetType().Name}: {ex.Message} → Block");
            return Decision.Block;
        }
        finally
        {
            TryCleanupPayload(payloadPath);
        }
    }

    // Translate user's decision into an action. Returns true if the
    // original method should run, false if it should be skipped.
    static bool ApplyDecision(int decision, LibraryAttribution lib)
    {
        switch (decision)
        {
            case Decision.Allow:
                return true;

            case Decision.AllowAndTrust:
                _trust.Trust(lib.AssemblyName);
                return true;

            case Decision.Kill:
                // Hard exit. Library code never resumes. Editor terminates.
                // User loses unsaved work — that's the price of intercept.
                try { _sink?.TryWrite(BuildKillEvent(lib)); } catch { }
                Environment.Exit(1);
                return false; // unreachable

            case Decision.KillAndRemove:
                // Delete the offending library from disk, THEN terminate the
                // editor. Removal runs before the exit so the attempt — and any
                // deferral of locked files to the next start — completes while
                // we're still alive. CompletePendingRemovals (next attach)
                // finishes anything the live editor still had locked.
                string removeOutcome;
                try { removeOutcome = TryRemoveLibrary(lib); }
                catch (Exception ex) { removeOutcome = $"remove threw {ex.GetType().Name}: {ex.Message}"; }
                Trace($"  KillAndRemove: {removeOutcome}");
                try { _sink?.TryWrite(BuildKillEvent(lib, removed: true, removeOutcome)); } catch { }
                Environment.Exit(1);
                return false; // unreachable

            case Decision.Block:
            default:
                EmitBlocked(lib);
                return false;
        }
    }

    // ───────────────────── Kill & remove library ─────────────────────
    // "Kill & remove library" (AlertDecision 4): delete the offending library's
    // folder from disk so it cannot run again, then Environment.Exit the editor.
    //
    // The delete races the live editor, which may still hold the compiled
    // assembly locked. Strategy: try an immediate recursive delete (succeeds
    // outright when s&box loaded the package in-memory / from a folder it
    // doesn't lock); if that throws, record the folder in a marker that
    // CompletePendingRemovals finishes on the NEXT attach — by then this
    // process has exited and freed the lock. No admin and no reboot required.

    // Resolve the …\Libraries\<name> folder for the attributed assembly, or null
    // when the assembly isn't under a Libraries\ tree (engine code, or an
    // in-memory load with no on-disk path). Walking up until the PARENT is
    // "Libraries" means we can only ever return a direct child of Libraries\ —
    // never Libraries\ itself, never anything above it.
    static string? ResolveLibraryRoot(string assemblyPath)
    {
        try
        {
            var full = Path.GetFullPath(assemblyPath);
            var dir = File.Exists(full)
                ? new DirectoryInfo(Path.GetDirectoryName(full)!)
                : new DirectoryInfo(full);
            while (dir?.Parent != null)
            {
                if (string.Equals(dir.Parent.Name, "Libraries", StringComparison.OrdinalIgnoreCase))
                    return dir.FullName;
                dir = dir.Parent;
            }
        }
        catch { }
        return null;
    }

    // Authoritative delete gate: true only when `path` is exactly a direct child
    // of a folder named "Libraries". Every Directory.Delete in this file is
    // guarded by this, so a malformed or forged path can never escape the
    // library tree.
    static bool IsDeletableLibraryRoot(string path)
    {
        try
        {
            var dir = new DirectoryInfo(Path.GetFullPath(path));
            return dir.Parent != null
                && string.Equals(dir.Parent.Name, "Libraries", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    static string TryRemoveLibrary(LibraryAttribution lib)
    {
        var path = lib.AssemblyPath;
        if (string.IsNullOrEmpty(path))
            return "attributed assembly has no on-disk path (in-memory load) — cannot locate a library folder; editor killed without removal";

        var root = ResolveLibraryRoot(path);
        if (root == null || !IsDeletableLibraryRoot(root))
            return $"attributed assembly is not inside a \\Libraries\\<name>\\ folder — refused to delete anything (path='{path}')";

        if (!Directory.Exists(root))
            return $"library folder already gone: '{root}'";

        try
        {
            Directory.Delete(root, recursive: true);
            return $"deleted library folder '{root}'";
        }
        catch (Exception ex)
        {
            // Editor still holds a handle (usually the compiled assembly under
            // \.bin\). Defer the remainder to the next attach, after we've exited.
            WritePendingRemoval(root);
            return $"library folder '{root}' is in use ({ex.GetType().Name}); "
                 + "remaining files scheduled for deletion on next editor start";
        }
    }

    // Marker file of library folders awaiting deletion — one absolute path per
    // line, alongside the trace log under %LOCALAPPDATA%\secbox.
    static readonly string PendingRemovalsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "secbox", "pending-removals.txt");

    static void WritePendingRemoval(string libraryRoot)
    {
        try
        {
            var dir = Path.GetDirectoryName(PendingRemovalsPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.AppendAllText(PendingRemovalsPath, libraryRoot + Environment.NewLine);
        }
        catch (Exception ex) { Trace($"WritePendingRemoval: {ex.GetType().Name}: {ex.Message}"); }
    }

    // Runs on every attach. Completes deletions a previous "Kill & remove
    // library" couldn't finish because the requesting editor still had the
    // assembly locked; that editor has since exited, so the folders can go now.
    // Re-validates every path against IsDeletableLibraryRoot — the marker file
    // is never trusted blindly.
    static void CompletePendingRemovals()
    {
        try
        {
            if (!File.Exists(PendingRemovalsPath)) return;

            var remaining = new List<string>();
            foreach (var raw in File.ReadAllLines(PendingRemovalsPath))
            {
                var root = raw.Trim();
                if (root.Length == 0) continue;
                if (!IsDeletableLibraryRoot(root))
                {
                    Trace($"CompletePendingRemovals: skip non-library path '{root}'");
                    continue;
                }
                if (!Directory.Exists(root)) { Trace($"CompletePendingRemovals: already gone '{root}'"); continue; }
                try { Directory.Delete(root, recursive: true); Trace($"CompletePendingRemovals: deleted '{root}'"); }
                catch (Exception ex) { Trace($"CompletePendingRemovals: still locked '{root}' ({ex.Message}) — keep for next start"); remaining.Add(root); }
            }

            if (remaining.Count == 0) File.Delete(PendingRemovalsPath);
            else File.WriteAllLines(PendingRemovalsPath, remaining);
        }
        catch (Exception ex) { Trace($"CompletePendingRemovals: {ex.GetType().Name}: {ex.Message}"); }
    }

    static string? WriteSuspendPayload(LibraryAttribution lib)
    {
        try
        {
            // Private per-user temp dir — deliberately NOT the AlertSpawner
            // watched folder. The synchronous in-process child reads this by
            // absolute path; the service must never see it (see SuspendAndDecide
            // step 2 for why a shared drop causes a duplicate dialog + file race).
            var dropDir = Path.Combine(Path.GetTempPath(), "secbox", "suspend");
            Directory.CreateDirectory(dropDir);
            var path = Path.Combine(dropDir,
                $"suspend-{DateTime.UtcNow:yyyyMMddTHHmmssfff}-{Guid.NewGuid():N}.json");
            var json = JsonSerializer.Serialize(new
            {
                severity = "Critical",
                kind = "ManagedProcessStart",
                target = $"{lib.AssemblyName}!{lib.MethodName}",
                callerAssembly = lib.AssemblyName,
                callerMethod = lib.MethodName,
                timestamp = DateTimeOffset.UtcNow.ToString("O"),
                pid = Environment.ProcessId,
                action = "Suspended",
                note = (string?)null,
            });
            File.WriteAllText(path, json);
            return path;
        }
        catch { return null; }
    }

    static void TryCleanupPayload(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    static string? ResolveAlertUiPath()
    {
        try
        {
            var dir = Path.GetDirectoryName(typeof(ManagedCallSensor).Assembly.Location);
            if (string.IsNullOrEmpty(dir)) return null;
            var exe = Path.Combine(dir, "SecboxAlertUI.exe");
            return File.Exists(exe) ? exe : null;
        }
        catch { return null; }
    }

    static SensorEvent BuildKillEvent(LibraryAttribution lib, bool removed = false, string? removeOutcome = null) => new(
        Sequence: Interlocked.Increment(ref _sequence),
        SensorId: "managed-call",
        Kind: SensorEventKind.BlockedManagedProcessStart,
        Timestamp: DateTimeOffset.UtcNow,
        Pid: Environment.ProcessId,
        Tid: Environment.CurrentManagedThreadId,
        Target: $"{lib.AssemblyName}!{lib.MethodName}",
        PayloadJson: JsonSerializer.Serialize(new
        {
            library = lib.AssemblyName,
            method = lib.MethodName,
            action = removed ? "KilledAndRemoved" : "Killed",
            reason = removed
                ? "user chose Kill & remove library from the AlertUI suspension dialog"
                : "user chose Kill from the AlertUI suspension dialog",
            removeOutcome,
        }));

    static void EmitSuspended(LibraryAttribution lib)
    {
        _sink?.TryWrite(new SensorEvent(
            Sequence: Interlocked.Increment(ref _sequence),
            SensorId: "managed-call",
            Kind: SensorEventKind.ManagedProcessStart,
            Timestamp: DateTimeOffset.UtcNow,
            Pid: Environment.ProcessId,
            Tid: Environment.CurrentManagedThreadId,
            Target: $"{lib.AssemblyName}!{lib.MethodName}",
            PayloadJson: JsonSerializer.Serialize(new
            {
                library = lib.AssemblyName,
                method = lib.MethodName,
                action = "Suspended",
                reason = "calling thread suspended pending user decision",
            })));
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
        // The secbox s&box library/adapter itself — ident "f4industries.secbox",
        // assemblies like "package.f4industries.secbox.editor". Its own
        // Process.Start calls are infrastructure, not library threats: the
        // adapter spawns SecboxAlertUI.exe (RuntimeMonitorCoordinator) and runs
        // msiexec (SentinelInstaller). Without this exclusion secbox flags
        // itself, and — worse — its AlertUI spawn is re-intercepted into a
        // recursive dialog storm. Never attribute/intercept our own code.
        || name.IndexOf("f4industries.secbox", StringComparison.OrdinalIgnoreCase) >= 0
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

    // ───────────────────────── Debug tracing ─────────────────────────
    // TEMPORARY diagnostic trace for the Tier E suspend path. Appends to
    // %LOCALAPPDATA%\secbox\managed-call-trace.log. Low volume — only fires on
    // Process.Start interception. Remove or gate behind an env var before ship.
    static readonly string TraceLogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "secbox", "managed-call-trace.log");
    static readonly object _traceGate = new();

    static void Trace(string msg)
    {
        try
        {
            var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff} "
                + $"[pid {Environment.ProcessId} t{Environment.CurrentManagedThreadId}] {msg}{Environment.NewLine}";
            lock (_traceGate) { File.AppendAllText(TraceLogPath, line); }
        }
        catch { /* tracing must never disturb the patched call */ }
    }

    static string SafeAsmLocation()
    {
        try { var l = typeof(ManagedCallSensor).Assembly.Location; return string.IsNullOrEmpty(l) ? "(in-memory)" : l; }
        catch { return "(unknown)"; }
    }

    static string SafeAlcName(Assembly asm)
    {
        try { return System.Runtime.Loader.AssemblyLoadContext.GetLoadContext(asm)?.Name ?? "(default)"; }
        catch { return "(error)"; }
    }

    static int SafePid(Process p)
    {
        try { return p.Id; } catch { return -1; }
    }

    // Make 0Harmony loadable by Harmony's runtime patcher.
    //
    // The s&box adapter loads Secbox.Core (and our 0Harmony.dll dependency)
    // into a COLLECTIBLE AssemblyLoadContext for hot-reload (SecboxCoreLoader,
    // isCollectible: true). Harmony's MonoMod backend patches by emitting
    // detour/trampoline code into a NON-collectible dynamic assembly in the
    // DEFAULT context, and that emitted code references 0Harmony by name. A
    // non-collectible assembly may not reference a collectible one, so every
    // Harmony.Patch() throws:
    //     Could not load file or assembly '0Harmony, …'.
    //     Operation is not supported. (0x80131515)
    // — patching ZERO methods and silently disabling all Tier E interception.
    //
    // Fix: pre-load 0Harmony into the Default (non-collectible) context BEFORE
    // the first `new Harmony(...)`. Resolution of Core's 0Harmony reference then
    // falls through our collectible ALC to Default and binds to this copy, which
    // the emitted detours can legally reference. Idempotent and best-effort:
    // if it can't run, patching simply fails as before (logged).
    // Set once we've installed the Default-ALC resolver for the MonoMod closure.
    static int _defaultResolverHooked;

    static void EnsureHarmonyLoadable()
    {
        try
        {
            var dir = Path.GetDirectoryName(typeof(ManagedCallSensor).Assembly.Location);
            if (string.IsNullOrEmpty(dir))
            {
                Trace("EnsureHarmonyLoadable: Core has no on-disk location — cannot stage MonoMod into Default");
                return;
            }

            // Harmony 2.4.x splits MonoMod into several assemblies (MonoMod.Core,
            // .RuntimeDetour, .Utils, .Backports, .ILHelpers …). 0Harmony AND all
            // of them must resolve to ONE copy in the Default (non-collectible)
            // context: MonoMod emits its detours there, a non-collectible
            // assembly may not reference a collectible one, and two copies of any
            // of these collide on type identity. Once 0Harmony is in Default, ITS
            // dependencies resolve via Default — which has no idea where our
            // dev/cache folder is — so install a Default resolver that serves the
            // whole 0Harmony/MonoMod.* closure from next to Core.dll.
            if (Interlocked.Exchange(ref _defaultResolverHooked, 1) == 0)
            {
                System.Runtime.Loader.AssemblyLoadContext.Default.Resolving += (ctx, name) =>
                {
                    var n = name.Name ?? "";
                    if (!string.Equals(n, "0Harmony", StringComparison.OrdinalIgnoreCase)
                        && !n.StartsWith("MonoMod", StringComparison.OrdinalIgnoreCase))
                        return null;
                    var p = Path.Combine(dir, n + ".dll");
                    if (!File.Exists(p)) { Trace($"Default.Resolving: {n} → not found at {p}"); return null; }
                    var loaded = ctx.LoadFromAssemblyPath(p);
                    Trace($"Default.Resolving: {n} v{loaded.GetName().Version} → Default ALC");
                    return loaded;
                };
                Trace("EnsureHarmonyLoadable: installed Default resolver for 0Harmony + MonoMod.*");
            }

            // Kick the chain off by ensuring 0Harmony itself is in Default; the
            // resolver above then pulls in MonoMod.Core/.RuntimeDetour/etc.
            PreloadIntoDefault("0Harmony");
        }
        catch (Exception ex)
        {
            Trace($"EnsureHarmonyLoadable: FAILED {ex.GetType().Name}: {ex.Message}");
        }
    }

    static void PreloadIntoDefault(string assemblyName)
    {
        try
        {
            var def = System.Runtime.Loader.AssemblyLoadContext.Default;
            foreach (var a in def.Assemblies)
            {
                if (string.Equals(a.GetName().Name, assemblyName, StringComparison.OrdinalIgnoreCase))
                {
                    Trace($"Preload: {assemblyName} already in Default ALC");
                    return;
                }
            }

            var dir = Path.GetDirectoryName(typeof(ManagedCallSensor).Assembly.Location);
            var path = string.IsNullOrEmpty(dir) ? null : Path.Combine(dir, assemblyName + ".dll");
            if (path == null || !File.Exists(path))
            {
                Trace($"Preload: {assemblyName}.dll NOT FOUND (dir='{dir ?? "(in-memory)"}')");
                return;
            }

            var asm = def.LoadFromAssemblyPath(path);
            Trace($"Preload: {asm.GetName().Name} v{asm.GetName().Version} → Default ALC");
        }
        catch (Exception ex)
        {
            Trace($"Preload: {assemblyName} FAILED {ex.GetType().Name}: {ex.Message}");
        }
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
