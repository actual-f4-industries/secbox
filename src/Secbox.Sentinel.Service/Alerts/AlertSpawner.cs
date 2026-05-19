using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Secbox.Sentinel.Service.Alerts;

// Watches %PROGRAMDATA%\secbox\alerts\ for *.json files dropped by the
// editor. On each new file, launches SecboxAlertUI.exe in the active
// console user's session via CreateProcessAsUser — so the dialog renders
// on the user's desktop even though the service runs as LocalSystem
// (Session 0). The launched process is independent of the editor — the
// editor can be paused, deadlocked, or crashed and the alert still fires.
//
// IPC choice: file drop instead of pipe. The editor's Harmony prefix
// writes the alert JSON synchronously and returns immediately. NTFS small
// writes are atomic and visible to FileSystemWatcher within milliseconds.
// If the editor freezes the instant after the write, the file is still
// on disk and we still process it.
//
// Drop folder is %PROGRAMDATA%\secbox\alerts\ — ACL'd to allow any
// authenticated user to write (so the editor running as the interactive
// user can drop). The service runs as LocalSystem and reads + deletes.
public sealed class AlertSpawner : BackgroundService
{
    public static string DropFolder =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "secbox", "alerts");

    readonly ILogger<AlertSpawner> _log;
    FileSystemWatcher? _watcher;

    public AlertSpawner(ILogger<AlertSpawner> log)
    {
        _log = log;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { Directory.CreateDirectory(DropFolder); }
        catch (Exception ex)
        {
            _log.LogError(ex, "AlertSpawner failed to create drop folder {Folder}", DropFolder);
            return Task.CompletedTask;
        }

        // Process any pre-existing drops first — editor may have written
        // them while the service was restarting.
        try
        {
            foreach (var f in Directory.EnumerateFiles(DropFolder, "*.json"))
            {
                HandleDrop(f);
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "AlertSpawner failed to drain pre-existing drops");
        }

        _watcher = new FileSystemWatcher(DropFolder, "*.json")
        {
            EnableRaisingEvents = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
        };
        _watcher.Created += (_, e) => HandleDrop(e.FullPath);
        _watcher.Renamed += (_, e) => HandleDrop(e.FullPath);
        _log.LogInformation("AlertSpawner watching {Folder}", DropFolder);

        stoppingToken.Register(() =>
        {
            try { if (_watcher != null) _watcher.EnableRaisingEvents = false; } catch { }
            try { _watcher?.Dispose(); } catch { }
        });
        return Task.CompletedTask;
    }

    void HandleDrop(string path)
    {
        // FileSystemWatcher fires on file CREATE which may precede the
        // writer's final flush. A tiny retry handles the race. If the
        // writer never completes we just give up and delete.
        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                if (!File.Exists(path)) return;
                using (var fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (fs.Length == 0) { Thread.Sleep(20); continue; }
                }
                LaunchAlertUI(path);
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(20);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "AlertSpawner failed on {Path}", path);
                try { File.Delete(path); } catch { }
                return;
            }
        }

        _log.LogWarning("Giving up on {Path} after retries", path);
        try { File.Delete(path); } catch { }
    }

    void LaunchAlertUI(string payloadPath)
    {
        var exe = ResolveAlertUiPath();
        if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
        {
            _log.LogError("SecboxAlertUI.exe not found near service binary; giving up on alert");
            try { File.Delete(payloadPath); } catch { }
            return;
        }

        var sessionId = GetActiveUserSessionId();
        if (sessionId < 0)
        {
            _log.LogWarning("No active console user session; cannot show alert UI (payload {Path})", payloadPath);
            // Leave the file in place — when a user logs in we'll pick it up
            // on next service start (the pre-drain pass at ExecuteAsync top).
            return;
        }

        try
        {
            // Win32 contract: when applicationName is non-null, commandLine
            // MUST still begin with the program name (it becomes argv[0]).
            // If we pass only the payload path, WPF sees it as argv[0] and
            // e.Args is empty — App.OnStartup throws "usage: …".
            CreateProcessInUserSession(
                (uint)sessionId,
                exe,
                $"\"{exe}\" \"{payloadPath}\"");
            _log.LogInformation("AlertUI launched in session {Sid} for {Path}", sessionId, payloadPath);
            // AlertUI deletes the payload file itself after reading.
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "CreateProcessAsUser failed for alert UI; deleting payload to avoid loop");
            try { File.Delete(payloadPath); } catch { }
        }
    }

    static string? ResolveAlertUiPath()
    {
        var baseDir = AppContext.BaseDirectory;
        var candidate = Path.Combine(baseDir, "SecboxAlertUI.exe");
        if (File.Exists(candidate)) return candidate;
        // Fallback: parent dir, useful in dev where the service runs from
        // bin\Release\net10.0-windows\win-x64\ and the UI is in
        // ..\..\..\..\Secbox.Sentinel.AlertUI\bin\...
        return null;
    }

    // ───────────────────────── Win32 plumbing ──────────────────────────

    static int GetActiveUserSessionId()
    {
        var sid = WTSGetActiveConsoleSessionId();
        return sid == 0xFFFFFFFF ? -1 : (int)sid;
    }

    static void CreateProcessInUserSession(uint sessionId, string exe, string commandLine)
    {
        IntPtr userToken = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        IntPtr envBlock = IntPtr.Zero;

        try
        {
            if (!WTSQueryUserToken(sessionId, out userToken))
                throw new InvalidOperationException(
                    $"WTSQueryUserToken({sessionId}) failed: 0x{Marshal.GetLastWin32Error():X}");

            var sa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>() };
            if (!DuplicateTokenEx(
                    userToken,
                    TOKEN_ALL_ACCESS,
                    ref sa,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenPrimary,
                    out primaryToken))
                throw new InvalidOperationException(
                    $"DuplicateTokenEx failed: 0x{Marshal.GetLastWin32Error():X}");

            if (!CreateEnvironmentBlock(out envBlock, primaryToken, inherit: false))
                envBlock = IntPtr.Zero; // best-effort; pass null below

            var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            var pi = new PROCESS_INFORMATION();

            // The string marshaller materialises commandLine into a fresh
            // LPWSTR buffer that Windows can mutate; we don't need to manage
            // the buffer ourselves. CharSet=Unicode is already on the
            // P/Invoke signature below. (The earlier "writable buffer" idea
            // didn't actually do anything — strings are immutable in C#.)
            var ok = CreateProcessAsUser(
                primaryToken,
                exe,
                commandLine,
                ref sa, ref sa,
                bInheritHandles: false,
                dwCreationFlags: CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
                lpEnvironment: envBlock,
                lpCurrentDirectory: Path.GetDirectoryName(exe),
                lpStartupInfo: ref si,
                lpProcessInformation: out pi);

            if (!ok)
                throw new InvalidOperationException(
                    $"CreateProcessAsUser failed: 0x{Marshal.GetLastWin32Error():X}");

            // We don't wait — fire and forget; the UI owns its own lifecycle.
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        finally
        {
            if (envBlock != IntPtr.Zero) DestroyEnvironmentBlock(envBlock);
            if (primaryToken != IntPtr.Zero) CloseHandle(primaryToken);
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }

    const uint TOKEN_ALL_ACCESS = 0x000F01FF;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    const uint CREATE_NEW_CONSOLE = 0x00000010;

    [DllImport("kernel32", SetLastError = true)]
    static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32", SetLastError = true)]
    static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

    [DllImport("advapi32", SetLastError = true)]
    static extern bool DuplicateTokenEx(
        IntPtr existingToken,
        uint desiredAccess,
        ref SECURITY_ATTRIBUTES tokenAttributes,
        SECURITY_IMPERSONATION_LEVEL impersonationLevel,
        TOKEN_TYPE tokenType,
        out IntPtr newToken);

    [DllImport("userenv", SetLastError = true)]
    static extern bool CreateEnvironmentBlock(out IntPtr envBlock, IntPtr token, bool inherit);

    [DllImport("userenv", SetLastError = true)]
    static extern bool DestroyEnvironmentBlock(IntPtr envBlock);

    [DllImport("kernel32", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUser(
        IntPtr token,
        string? applicationName,
        string commandLine,
        ref SECURITY_ATTRIBUTES processAttributes,
        ref SECURITY_ATTRIBUTES threadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    enum SECURITY_IMPERSONATION_LEVEL { SecurityAnonymous, SecurityIdentification, SecurityImpersonation, SecurityDelegation }
    enum TOKEN_TYPE { TokenPrimary = 1, TokenImpersonation = 2 }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute;
        public int dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
}
