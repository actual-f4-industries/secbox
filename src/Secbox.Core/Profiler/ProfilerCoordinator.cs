using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Diagnostics.NETCore.Client;

namespace Secbox.Core.Profiler;

// Locates the native profiler binary in the bridge cache folder beside
// this assembly, attaches it via DiagnosticsClient, then resolves its
// exported function pointers via NativeLibrary so ProfilerSensor can call
// them WITHOUT P/Invoke + DllImport.
//
// Why no P/Invoke / SetDllImportResolver: the resolver-based path is
// fragile across AssemblyLoadContext reloads — the runtime caches the
// resolver registration in a ConditionalWeakTable keyed on Assembly, and
// in practice the table can end up holding entries that don't fire for
// our reloaded Core. The symptom is exactly what we hit: SetDllImportResolver
// throws "A resolver is already set", but the lookup at P/Invoke time
// doesn't actually invoke our resolver, falling back to default lookup
// against "secbox-profiler.dll" which doesn't exist (file is named
// secbox-profiler-win-x64.dll). Function-pointer binding sidesteps all
// of that — we LoadLibrary the absolute path ourselves and GetExport
// every symbol we need.
//
// SHA-256 verification of the profiler DLL is done by the s&box adapter
// (CorePolicy.CoreFiles in the adapter source) — that's the trust anchor
// for the bridge bundle. Core does not re-verify.
public static class ProfilerCoordinator
{
    public const string NativeLibName = "secbox-profiler";

    // {53C5B321-7B0E-4F8B-A3D9-5EC5B0A3F101} — mirror of the native CLSID.
    public static readonly Guid ProfilerGuid = new("53C5B321-7B0E-4F8B-A3D9-5EC5B0A3F101");

    static readonly SemaphoreSlim _initLock = new(1, 1);
    static bool _attached;
    static string? _resolvedPath;
    static IntPtr _moduleHandle;
    static IntPtr _fpRegisterCallback;
    static IntPtr _fpDrainRing;
    static IntPtr _fpGetStatus;

    public static bool IsAttached => _attached;
    public static string? AttachedPath => _resolvedPath;

    // Exported function pointers. Null until EnsureAttachedAsync completes.
    public static IntPtr RegisterCallbackFn => _fpRegisterCallback;
    public static IntPtr DrainRingFn => _fpDrainRing;
    public static IntPtr GetStatusFn => _fpGetStatus;

    public static async Task EnsureAttachedAsync(CancellationToken ct)
    {
        if (_attached) return;
        await _initLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_attached) return;
            Diag("EnsureAttachedAsync: begin");
            var path = LocateProfilerBinary();
            Diag($"EnsureAttachedAsync: located profiler at '{path}', size={new FileInfo(path).Length:N0} bytes");
            _resolvedPath = path;
            await AttachAsync(path, ct).ConfigureAwait(false);
            BindFunctionPointers(path);
            _attached = true;
            Diag("EnsureAttachedAsync: complete (attached=true)");
        }
        catch (Exception ex)
        {
            Diag($"EnsureAttachedAsync: THREW {ex.GetType().Name}: {ex.Message}");
            throw;
        }
        finally { _initLock.Release(); }
    }

    static string LocateProfilerBinary()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            || RuntimeInformation.OSArchitecture != Architecture.X64)
        {
            throw new PlatformNotSupportedException(
                $"Profiler (Tier B) not available on {RuntimeInformation.OSDescription} " +
                $"{RuntimeInformation.OSArchitecture}. Only win-x64 is shipped today.");
        }

        const string fileName = "secbox-profiler-win-x64.dll";
        var asmLocation = typeof(ProfilerCoordinator).Assembly.Location;
        if (string.IsNullOrEmpty(asmLocation))
            throw new InvalidOperationException(
                "Secbox.Core's Assembly.Location is empty — cannot resolve profiler path.");

        var coreDir = Path.GetDirectoryName(asmLocation)!;
        var profilerPath = Path.Combine(coreDir, fileName);
        if (!File.Exists(profilerPath))
        {
            throw new FileNotFoundException(
                $"Native profiler not found at {profilerPath}. " +
                "The s&box adapter is responsible for downloading and SHA-256-verifying " +
                $"{fileName} into the same cache folder as Secbox.Core.dll. " +
                "Check CorePolicy.CoreFiles in the adapter source.",
                profilerPath);
        }

        return profilerPath;
    }

    // Loads the native profiler (returns the existing CLR-loaded handle on
    // Windows because the OS de-duplicates LoadLibrary by absolute path)
    // and resolves the three exported function pointers ProfilerSensor uses.
    static void BindFunctionPointers(string profilerPath)
    {
        Diag("BindFunctionPointers: begin");
        try
        {
            _moduleHandle = NativeLibrary.Load(profilerPath);
            Diag($"BindFunctionPointers: NativeLibrary.Load handle=0x{_moduleHandle.ToInt64():x}");

            _fpRegisterCallback = NativeLibrary.GetExport(_moduleHandle, "Secbox_RegisterCallback");
            _fpDrainRing        = NativeLibrary.GetExport(_moduleHandle, "Secbox_DrainRing");
            _fpGetStatus        = NativeLibrary.GetExport(_moduleHandle, "Secbox_GetStatus");

            Diag($"BindFunctionPointers: exports resolved " +
                 $"RegisterCallback=0x{_fpRegisterCallback.ToInt64():x} " +
                 $"DrainRing=0x{_fpDrainRing.ToInt64():x} " +
                 $"GetStatus=0x{_fpGetStatus.ToInt64():x}");
        }
        catch (Exception ex)
        {
            Diag($"BindFunctionPointers: THREW {ex.GetType().Name}: {ex.Message}");
            throw;
        }
    }

    static async Task AttachAsync(string profilerPath, CancellationToken ct)
    {
        Diag($"AttachAsync: begin pid={Environment.ProcessId} path='{profilerPath}'");
        var client = new DiagnosticsClient(Environment.ProcessId);
        try
        {
            await Task.Run(() =>
                client.AttachProfiler(
                    attachTimeout: TimeSpan.FromSeconds(10),
                    profilerGuid: ProfilerGuid,
                    profilerPath: profilerPath), ct).ConfigureAwait(false);
            Diag("AttachAsync: DiagnosticsClient.AttachProfiler returned OK");
        }
        catch (ServerErrorException ex) when (ex.Message.Contains("0x8013136A", StringComparison.OrdinalIgnoreCase))
        {
            Diag("AttachAsync: another profiler already attached (CORPROF_E_PROFILER_ALREADY_ACTIVE)");
            throw new InvalidOperationException(
                "Another CLR profiler is already attached to this editor process. " +
                "secbox runtime monitoring degrades to non-profiler tiers.", ex);
        }
        catch (Exception ex)
        {
            Diag($"AttachAsync: DiagnosticsClient.AttachProfiler THREW {ex.GetType().Name}: {ex.Message}");
            throw;
        }
    }

    // Diagnostic sink — writes to %LOCALAPPDATA%/secbox/profiler-diag.log.
    // Path is OUTSIDE the per-version cache folder so it survives reloads.
    static readonly object _diagLock = new();
    public static string DiagLogPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "secbox", "profiler-diag.log");

    static void Diag(string message)
    {
        try
        {
            lock (_diagLock)
            {
                var dir = Path.GetDirectoryName(DiagLogPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                var line = $"{DateTime.UtcNow:HH:mm:ss.fff} [tid={Environment.CurrentManagedThreadId:D2}] {message}\n";
                File.AppendAllText(DiagLogPath, line, Encoding.UTF8);
            }
        }
        catch { /* never throw from logger */ }
    }
}
