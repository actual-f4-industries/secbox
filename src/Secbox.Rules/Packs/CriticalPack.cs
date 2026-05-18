using Secbox.Contracts;

namespace Secbox.Rules.Packs;

// Always-flag attack patterns — anything matching these is Critical regardless
// of context, regardless of whether the engine whitelist also covers it.
// Assembly-agnostic patterns (`*/Member`) so an attacker can't dodge the rule
// by shipping a forwarder type from a custom assembly name.
public sealed class CriticalPack : IRulePack
{
    public const string PackId = "critical.v1";
    public const string PackVersion = "1.0.0";

    public RulePackInfo Info { get; }
    public IReadOnlyList<Rule> Rules { get; }

    public CriticalPack()
    {
        var rules = new List<Rule>();
        AddCategory(rules, "interop", "P/Invoke and native interop", InteropPatterns);
        AddCategory(rules, "process", "Process spawning", ProcessPatterns);
        AddCategory(rules, "dynamic-code", "Dynamic assembly load / IL emit / scripting", DynamicCodePatterns);
        AddCategory(rules, "raw-network", "Raw network — sockets, WebClient, listeners", RawNetworkPatterns);
        AddCategory(rules, "filesystem", "Direct BCL filesystem access (use Sandbox.Filesystem instead)", FilesystemPatterns);
        AddCategory(rules, "reflection", "Reflection-based dynamic invocation", ReflectionPatterns);
        AddCategory(rules, "environment", "Environment / registry / OS info gathering", EnvironmentPatterns);

        Rules = rules;
        Info = new RulePackInfo(
            Id: PackId,
            Version: PackVersion,
            Source: "Secbox.Rules.Packs.CriticalPack",
            Description: "Always-flag attack patterns. Matched references always emit Critical findings regardless of engine whitelist.",
            RuleCount: rules.Count);
    }

    static void AddCategory(List<Rule> sink, string category, string rationale, string[] patterns)
    {
        int i = 0;
        foreach (var p in patterns)
        {
            sink.Add(new Rule(
                Id: $"critical.{category}.{++i:D3}",
                Severity: Severity.Critical,
                Pattern: p,
                Rationale: rationale,
                Category: category));
        }
    }

    public static readonly string[] InteropPatterns = new[]
    {
        "*/System.Runtime.InteropServices.DllImportAttribute*",
        "*/System.Runtime.InteropServices.LibraryImportAttribute*",
        "*/System.Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer*",
        "*/System.Runtime.InteropServices.Marshal.GetFunctionPointerForDelegate*",
        "*/System.Runtime.InteropServices.Marshal.AllocHGlobal*",
        "*/System.Runtime.InteropServices.Marshal.Copy*",
        "*/System.Runtime.InteropServices.Marshal.PtrToStructure*",
        "*/System.Runtime.InteropServices.Marshal.StructureToPtr*",
        "*/System.Runtime.InteropServices.Marshal.WriteByte*",
        "*/System.Runtime.InteropServices.Marshal.WriteInt32*",
        "*/System.Runtime.InteropServices.Marshal.WriteIntPtr*",
        "*/System.Runtime.InteropServices.NativeLibrary*",
        "*/System.Runtime.InteropServices.SuppressGCTransitionAttribute*",
        "*/System.Runtime.CompilerServices.UnsafeAccessorAttribute*",
    };

    public static readonly string[] ProcessPatterns = new[]
    {
        "*/System.Diagnostics.Process*",
        "*/System.Diagnostics.ProcessStartInfo*",
    };

    public static readonly string[] DynamicCodePatterns = new[]
    {
        "*/System.Reflection.Assembly.Load*",
        "*/System.Reflection.Assembly.LoadFile*",
        "*/System.Reflection.Assembly.LoadFrom*",
        "*/System.Reflection.Assembly.UnsafeLoadFrom*",
        "*/System.Runtime.Loader.AssemblyLoadContext*",
        "*/System.Reflection.Emit.*",
        "*/Microsoft.CodeAnalysis.CSharp.Scripting.*",
        "*/Microsoft.CodeAnalysis.Scripting.*",
        "*/System.Linq.Expressions.Expression.Compile*",
    };

    public static readonly string[] RawNetworkPatterns = new[]
    {
        "*/System.Net.Sockets.*",
        "*/System.Net.NetworkInformation.*",
        "*/System.Net.HttpListener*",
        "*/System.Net.WebClient*",
        "*/System.Net.WebRequest*",
        "*/System.Net.FtpWebRequest*",
        "*/System.Net.Dns.*",
    };

    public static readonly string[] FilesystemPatterns = new[]
    {
        "*/System.IO.File.*",
        "*/System.IO.Directory.*",
        "*/System.IO.DirectoryInfo*",
        "*/System.IO.FileInfo*",
        "*/System.IO.FileStream*",
        "*/System.IO.FileSystemWatcher*",
        "*/System.IO.DriveInfo*",
        "*/System.IO.IsolatedStorage.*",
    };

    public static readonly string[] ReflectionPatterns = new[]
    {
        "*/System.Reflection.MethodInfo.Invoke*",
        "*/System.Reflection.MethodBase.Invoke*",
        "*/System.Reflection.ConstructorInfo.Invoke*",
        "*/System.Reflection.PropertyInfo.GetValue*",
        "*/System.Reflection.PropertyInfo.SetValue*",
        "*/System.Reflection.FieldInfo.GetValue*",
        "*/System.Reflection.FieldInfo.SetValue*",
        "*/System.Activator.CreateInstance*",
        "!*/System.Activator.CreateInstance<T>()",
        "*/System.Delegate.CreateDelegate*",
        "*/System.Type.GetType*",
        "*/System.Type.InvokeMember*",
        "*/System.Type.GetMethods*",
        "*/System.Type.GetMethod*",
        "*/System.Type.GetFields*",
        "*/System.Type.GetField*",
        "*/System.Type.GetProperties*",
        "*/System.Type.GetProperty*",
        "*/System.Type.GetConstructors*",
        "*/System.Type.GetConstructor*",
        "*/System.Type.GetMembers*",
        "*/System.Type.GetMember*",
    };

    public static readonly string[] EnvironmentPatterns = new[]
    {
        "*/System.Environment.GetEnvironmentVariable*",
        "*/System.Environment.GetEnvironmentVariables*",
        "*/System.Environment.GetCommandLineArgs*",
        "*/System.Environment.get_UserName*",
        "*/System.Environment.get_UserDomainName*",
        "*/System.Environment.get_MachineName*",
        "*/System.Environment.GetFolderPath*",
        "*/System.Environment.SetEnvironmentVariable*",
        "*/System.Environment.Exit*",
        "*/System.Environment.FailFast*",
        "*/Microsoft.Win32.Registry*",
        "*/Microsoft.Win32.RegistryKey*",
    };

    // String literal needles flagged in `ldstr` operands and source string
    // literals. Presence of these often signals native shellouts or DLL names
    // being loaded dynamically.
    public static readonly string[] SuspiciousStringLiterals = new[]
    {
        "kernel32", "ntdll", "advapi32", "user32", "gdi32",
        "shell32", "ws2_32", "wininet", "urlmon", "iphlpapi",
        "powershell", "cmd.exe", "/bin/sh", "/bin/bash",
        "rundll32", "regsvr32", "mshta.exe", "wmic",
        "VirtualAlloc", "VirtualProtect",
        "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
        "NtCreateSection", "RtlMoveMemory", "SetWindowsHookEx",
    };

    // Build a RuleSet matcher that includes every pattern from this pack —
    // convenience for finders that want to do bulk matching.
    public RuleSet BuildMatcher()
    {
        var rs = new RuleSet();
        foreach (var rule in Rules) rs.AddRule(rule.Pattern);
        return rs;
    }
}
