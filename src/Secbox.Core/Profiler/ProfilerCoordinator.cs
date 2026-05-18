using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Diagnostics.NETCore.Client;

namespace Secbox.Core.Profiler;

// Owns the lifecycle of the native profiler:
//   1. Extracts the platform-appropriate native binary from this assembly's
//      embedded resources to a per-user cache.
//   2. Verifies its SHA-256 against ProfilerHashes.
//   3. Asks the runtime to attach it via DiagnosticsClient.AttachProfiler.
//   4. Returns the resolved cache path so the P/Invoke loader can find it.
//
// Idempotent — calling EnsureAttachedAsync twice is a no-op after the first
// successful attach.
public static class ProfilerCoordinator
{
    // P/Invoke LibName — the runtime resolves "secbox-profiler" through the
    // platform DLL search rules. We help by AssemblyLoadContext-loading the
    // native binary from our cache before any P/Invoke fires; see Attach.
    public const string NativeLibName = "secbox-profiler";

    // {53C5B321-7B0E-4F8B-A3D9-5EC5B0A3F101} — mirror of the native CLSID.
    public static readonly Guid ProfilerGuid = new("53C5B321-7B0E-4F8B-A3D9-5EC5B0A3F101");

    static readonly SemaphoreSlim _initLock = new(1, 1);
    static bool _attached;
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
            var path = ExtractAndVerify();
            await AttachAsync(path, ct).ConfigureAwait(false);
            _resolvedPath = path;
            _attached = true;
        }
        finally { _initLock.Release(); }
    }

    static string ExtractAndVerify()
    {
        var (resourceName, expectedHash, fileName) = SelectPlatformResource();
        var asm = typeof(ProfilerCoordinator).Assembly;

        using var stream = asm.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException(
                $"Embedded profiler resource missing: {resourceName}. " +
                "Build pipeline did not bundle the native blob.");

        var cacheDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "secbox", "profiler",
            asm.GetName().Version?.ToString() ?? "dev");
        Directory.CreateDirectory(cacheDir);

        var cachePath = Path.Combine(cacheDir, fileName);
        byte[] bytes;
        using (var ms = new MemoryStream()) { stream.CopyTo(ms); bytes = ms.ToArray(); }

        var actualHash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (!expectedHash.Equals(actualHash, StringComparison.OrdinalIgnoreCase)
            && !IsPlaceholderHash(expectedHash))
        {
            throw new InvalidOperationException(
                $"Profiler hash mismatch for {fileName}. " +
                $"Expected {expectedHash}, got {actualHash}. Refusing to attach.");
        }

        if (!File.Exists(cachePath) || !SafeReadAllBytes(cachePath).SequenceEqual(bytes))
            File.WriteAllBytes(cachePath, bytes);

        return cachePath;
    }

    static byte[] SafeReadAllBytes(string p)
    {
        try { return File.ReadAllBytes(p); } catch { return Array.Empty<byte>(); }
    }

    static bool IsPlaceholderHash(string h) =>
        h.All(c => c == '0') || string.IsNullOrEmpty(h);

    static (string ResourceName, string ExpectedHash, string FileName) SelectPlatformResource()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            && RuntimeInformation.OSArchitecture == Architecture.X64)
        {
            return ("Secbox.Core.Profiler.EmbeddedProfilerResources.secbox-profiler-win-x64.dll",
                    ProfilerHashes.ExpectedSha256WinX64,
                    "secbox-profiler-win-x64.dll");
        }

        throw new PlatformNotSupportedException(
            $"Profiler (Tier B) not available on {RuntimeInformation.OSDescription} " +
            $"{RuntimeInformation.OSArchitecture}. Only win-x64 is shipped today.");
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
