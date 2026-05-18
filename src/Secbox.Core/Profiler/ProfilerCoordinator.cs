using System.Runtime.InteropServices;
using Microsoft.Diagnostics.NETCore.Client;

namespace Secbox.Core.Profiler;

// Locates the native profiler binary in the bridge cache folder beside
// this assembly, then attaches it via DiagnosticsClient.
//
// SHA-256 verification of the profiler DLL is done by the s&box adapter
// (CorePolicy.CoreFiles[secbox-profiler-win-x64.dll] in the adapter source)
// — that's the trust anchor for the bridge bundle. Core does not re-verify:
// the adapter is the entity that owns the pinned hashes and refuses to
// write any mismatched blob to the cache. Re-verifying here would only
// duplicate the check against a potentially-compromised hash constant
// inside Core itself.
//
// Idempotent — calling EnsureAttachedAsync twice is a no-op after the
// first successful attach.
public static class ProfilerCoordinator
{
    // P/Invoke LibName — runtime resolves "secbox-profiler" against the
    // cache folder where this assembly was loaded from (same folder).
    public const string NativeLibName = "secbox-profiler";

    // {53C5B321-7B0E-4F8B-A3D9-5EC5B0A3F101} — mirror of the native CLSID.
    public static readonly Guid ProfilerGuid = new("53C5B321-7B0E-4F8B-A3D9-5EC5B0A3F101");

    static readonly SemaphoreSlim _initLock = new(1, 1);
    static bool _attached;
    static bool _resolverRegistered;
    static string? _resolvedPath;

    public static bool IsAttached => _attached;
    public static string? AttachedPath => _resolvedPath;

    public static async Task EnsureAttachedAsync(CancellationToken ct)
    {
        if (_attached) return;
        await _initLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_attached) return;
            var path = LocateProfilerBinary();
            _resolvedPath = path;
            RegisterDllImportResolverOnce();   // before any P/Invoke in ProfilerSensor
            await AttachAsync(path, ct).ConfigureAwait(false);
            _attached = true;
        }
        finally { _initLock.Release(); }
    }

    // ProfilerSensor's P/Invokes reference NativeLibName ("secbox-profiler"),
    // but the actual file on disk is "secbox-profiler-win-x64.dll" — the
    // platform suffix has to live in the filename so future cross-platform
    // builds can ship side-by-side. The loader's name-based lookup won't
    // bridge that gap on its own. SetDllImportResolver redirects every
    // P/Invoke against NativeLibName to LoadLibrary(absolute cached path).
    //
    // CoreCLR allows one resolver per Assembly, so we gate on the local
    // flag AND swallow InvalidOperationException — the latter handles
    // edge cases like:
    //   - The s&box adapter triggered a Core hot-reload; the previous
    //     Core's Assembly is still in the runtime's resolver table even
    //     though our static state was reset.
    //   - Someone else (a profiling tool, another library) already
    //     registered a resolver against this Assembly.
    // In both cases the existing resolver references the SAME static
    // _resolvedPath via the captured closure (since it's the same Core
    // load), or — if it's a foreign resolver — the downstream P/Invoke
    // will fail with DllNotFoundException, which carries a clearer cause
    // than this "resolver already set" message.
    static void RegisterDllImportResolverOnce()
    {
        if (_resolverRegistered) return;
        try
        {
            NativeLibrary.SetDllImportResolver(
                typeof(ProfilerCoordinator).Assembly,
                static (libraryName, _, _) =>
                {
                    if (libraryName != NativeLibName) return IntPtr.Zero;
                    var p = _resolvedPath;
                    if (string.IsNullOrEmpty(p)) return IntPtr.Zero;
                    return NativeLibrary.TryLoad(p, out var handle) ? handle : IntPtr.Zero;
                });
        }
        catch (InvalidOperationException)
        {
            // Resolver already set for this assembly — accept and move on.
            // See block comment above for the reasoning.
        }
        _resolverRegistered = true;
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
        var coreDir = Path.GetDirectoryName(typeof(ProfilerCoordinator).Assembly.Location)
            ?? throw new InvalidOperationException(
                "Could not resolve Secbox.Core assembly directory — profiler lookup failed.");

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

    static async Task AttachAsync(string profilerPath, CancellationToken ct)
    {
        var client = new DiagnosticsClient(Environment.ProcessId);
        try
        {
            // Synchronous under the hood; wrap with Task.Run to keep our
            // ConfigureAwait(false) story clean and to surface OperationCanceled
            // promptly if the caller cancels.
            await Task.Run(() =>
                client.AttachProfiler(
                    attachTimeout: TimeSpan.FromSeconds(10),
                    profilerGuid: ProfilerGuid,
                    profilerPath: profilerPath), ct).ConfigureAwait(false);
        }
        catch (ServerErrorException ex) when (ex.Message.Contains("0x8013136A", StringComparison.OrdinalIgnoreCase))
        {
            // CORPROF_E_PROFILER_ALREADY_ACTIVE — another profiler attached first.
            throw new InvalidOperationException(
                "Another CLR profiler is already attached to this editor process. " +
                "secbox runtime monitoring degrades to non-profiler tiers.", ex);
        }
    }
}
