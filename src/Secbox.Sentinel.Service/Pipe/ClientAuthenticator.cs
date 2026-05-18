using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace Secbox.Sentinel.Service.Pipe;

// Authenticates pipe clients by inspecting the calling process. Two checks
// in order, both must pass:
//   1. Caller process image must exist on disk and be under a trusted root
//      (Steam install path for editor.exe, or %LOCALAPPDATA%/secbox/* for
//      our own client binaries).
//   2. If we have a pinned publisher cert thumbprint, the caller image's
//      Authenticode signature must chain to it.
//
// The strict checks default to "warn-only" while we're still pre-signing.
// Once a real cert is wired into the release pipeline, flip RequireSigned
// to true and remove the warn-only branch.
public sealed class ClientAuthenticator
{
    readonly ILogger<ClientAuthenticator> _log;

    public ClientAuthenticator(ILogger<ClientAuthenticator> log) { _log = log; }

    public bool RequireSigned { get; set; } = false;
    public string? PinnedPublisherThumbprint { get; set; }

    // Roots that callers are allowed to live under. Anything else is rejected.
    public List<string> AllowedRoots { get; } = new()
    {
        @"C:\Program Files (x86)\Steam\steamapps\common\sbox\",
        @"C:\Program Files\Steam\steamapps\common\sbox\",
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "secbox") + @"\",
    };

    public AuthResult Authenticate(NamedPipeServerStream pipe, int claimedEditorPid)
    {
        int callerPid;
        try { callerPid = GetClientPid(pipe); }
        catch (Exception ex)
        {
            return AuthResult.Deny($"could not resolve client pid: {ex.Message}");
        }

        // Sanity: the claimed editor pid in Hello must match the connecting
        // process. We only allow self-attribution. A separate elevated tool
        // would use a different (future) handshake.
        if (claimedEditorPid != callerPid)
            return AuthResult.Deny($"editorPid {claimedEditorPid} != connecting pid {callerPid}");

        string imagePath;
        try
        {
            using var proc = Process.GetProcessById(callerPid);
            imagePath = proc.MainModule?.FileName ?? "";
        }
        catch (Exception ex)
        {
            return AuthResult.Deny($"could not resolve image path for pid {callerPid}: {ex.Message}");
        }
        if (string.IsNullOrEmpty(imagePath)) return AuthResult.Deny("empty image path");

        // Root check.
        var allowed = AllowedRoots.Any(r =>
            imagePath.StartsWith(r, StringComparison.OrdinalIgnoreCase));
        if (!allowed)
            return AuthResult.Deny($"image not under any allowed root: {imagePath}");

        // Signature check (advisory until RequireSigned flips on).
        if (!string.IsNullOrEmpty(PinnedPublisherThumbprint))
        {
            try
            {
                var cert = X509Certificate.CreateFromSignedFile(imagePath);
                var thumb = new X509Certificate2(cert).Thumbprint ?? "";
                var match = thumb.Equals(PinnedPublisherThumbprint, StringComparison.OrdinalIgnoreCase);
                if (!match)
                {
                    var msg = $"image signature thumbprint {thumb} does not match pinned {PinnedPublisherThumbprint}";
                    if (RequireSigned) return AuthResult.Deny(msg);
                    _log.LogWarning(msg + " (warn-only)");
                }
            }
            catch (Exception ex)
            {
                if (RequireSigned) return AuthResult.Deny($"signature check failed: {ex.Message}");
                _log.LogWarning("signature check failed (warn-only): {Msg}", ex.Message);
            }
        }

        return AuthResult.Allow(callerPid, imagePath);
    }

    // GetNamedPipeClientProcessId — P/Invoke; no managed equivalent on the
    // pipe stream API.
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetNamedPipeClientProcessId(IntPtr Pipe, out uint ClientProcessId);

    static int GetClientPid(NamedPipeServerStream pipe)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid))
            throw new InvalidOperationException($"GetNamedPipeClientProcessId failed, win32={Marshal.GetLastWin32Error()}");
        return (int)pid;
    }
}

public readonly record struct AuthResult(bool Ok, int CallerPid, string? ImagePath, string? Reason)
{
    public static AuthResult Allow(int pid, string image) => new(true, pid, image, null);
    public static AuthResult Deny(string reason) => new(false, 0, null, reason);
}
