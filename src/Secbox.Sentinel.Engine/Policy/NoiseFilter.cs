using Secbox.Sentinel.Contracts;

namespace Secbox.Sentinel.Engine.Policy;

// Cross-cutting pre-filter applied to every kernel event BEFORE per-
// subscription matching. Drops events that no plausible subscriber wants:
// system-DLL probes, registry reads, our own self-writes (which would
// otherwise create a runaway feedback loop). Runs once per event.
//
// ETW does not carry managed-stack attribution, so the editor's normal
// activity (asset loads, COM/codec lookups, system DLL probes) shows up
// in the same stream as library activity. Without filtering, the editor's
// own noise drowns out everything actionable — and at >70 events/s, the
// pipe transport + JSON serialisation cost grinds the editor to a halt.
//
// What this DOES NOT do:
//   * Library attribution. We can't say "this came from package.MyLib.dll"
//     without user-mode stack walks + JIT symbol resolution. The remaining
//     signal after this filter is "things any subscriber should care about
//     regardless of attribution".
//   * Tier B (profiler) is the layer that does managed call attribution.
//
// Conservative principle: only drop events that have NO plausible security
// signal. When in doubt, keep.
public static class NoiseFilter
{
    public static bool IsNoise(KernelEvent ev)
    {
        // Registry reads are pure noise — COM activation, codec enumeration,
        // shell extensions, font lookups. Mutations (RegSetValue / RegDelete*)
        // still flow through and are surfaced.
        if (ev.Kind == KernelEventKind.RegOpenKey) return true;

        // Path-based exclusions only apply to file & native image load
        // events. ProcessStart / ProcessStop / network events carry path
        // metadata that's informational, not a filterable noise signal —
        // a library spawning `C:\Windows\System32\cmd.exe` is interesting
        // even though the image lives in a system path.
        if (!IsPathFilterable(ev.Kind)) return false;

        var path = ev.Path ?? ev.Target;
        if (string.IsNullOrEmpty(path)) return false;

        // Windows + Program Files: signed MS / vendor binaries. Image-load
        // and file-open events for these add no signal — a malicious library
        // can't write here without elevation, and reads are the OS doing its
        // normal job (DLL probes, manifest lookups, side-by-side resolution).
        if (StartsWithIcs(path, @"C:\Windows\")) return true;
        if (StartsWithIcs(path, @"C:\Program Files\")) return true;
        if (StartsWithIcs(path, @"C:\Program Files (x86)\")) return true;

        // s&box engine install dir. Editor reads thousands of files here per
        // session. A library code-path *could* theoretically write to the
        // install dir, but it would need admin and would be visible via the
        // file-system itself, not the runtime ETW stream.
        if (ContainsIcs(path, @"\sbox\bin\")) return true;
        if (ContainsIcs(path, @"\sbox\addons\")) return true;
        if (ContainsIcs(path, @"\sbox\core\")) return true;

        // Editor's own writable state — settings, caches, logs.
        if (ContainsIcs(path, @"\AppData\Local\sbox\")) return true;
        if (ContainsIcs(path, @"\AppData\Roaming\sbox\")) return true;
        if (ContainsIcs(path, @"\.source2\temp\")) return true;

        // Self-exclusion. CRITICAL: secbox writes to %LOCALAPPDATA%\secbox\
        // (config, logs, downloaded core DLLs). Every write triggers ETW
        // which forwards to the editor which writes the log entry which is
        // a write which triggers ETW... unbounded feedback loop.
        if (ContainsIcs(path, @"\AppData\Local\secbox\")) return true;

        return false;
    }

    static bool IsPathFilterable(KernelEventKind k) => k switch
    {
        KernelEventKind.FileCreate or KernelEventKind.FileWrite
            or KernelEventKind.FileDelete or KernelEventKind.FileRename
            or KernelEventKind.FileSetSecurity => true,
        KernelEventKind.ImageLoad => true,
        _ => false,
    };

    static bool StartsWithIcs(string s, string prefix) =>
        s.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

    static bool ContainsIcs(string s, string sub) =>
        s.IndexOf(sub, StringComparison.OrdinalIgnoreCase) >= 0;
}
