using Secbox.Contracts;

namespace Secbox.Scanner.Finders;

// Flags unmanaged binaries shipped inside library packages. Three signals:
//  1. .dll files whose PE header lacks a CLI directory (= native DLL)
//  2. .so / .dylib (unix shared libraries)
//  3. .exe / .bat / .ps1 / .sh (standalone executables, shellable)
//
// All produce Critical findings — there is no legitimate reason for a
// managed-library package to include any of these without explicit, separately
// reviewed opt-in by the consumer.
public sealed class NativeBinaryFinder : IFinder
{
    public string Id => "native-binary";
    public string Description => "Detects unmanaged binaries (.dll/.so/.dylib/.exe/.bat/.ps1/.sh) inside package folders.";

    static readonly string[] NativeUnix = { ".so", ".dylib" };
    static readonly string[] Executable = { ".exe", ".bat", ".ps1", ".sh", ".cmd" };

    public bool AppliesTo(ScanTarget target) => target is FolderTarget;

    public Task<IReadOnlyList<Finding>> ScanAsync(
        ScanTarget target,
        ScanContext context,
        CancellationToken ct = default)
    {
        var findings = new List<Finding>();
        if (target is not FolderTarget folder) return Task.FromResult<IReadOnlyList<Finding>>(findings);

        if (!Directory.Exists(folder.Path)) return Task.FromResult<IReadOnlyList<Finding>>(findings);

        foreach (var path in Directory.EnumerateFiles(folder.Path, "*", SearchOption.AllDirectories))
        {
            ct.ThrowIfCancellationRequested();

            var rel = SafeRel(folder.Path, path);
            if (rel.Contains("/obj/") || rel.Contains("\\obj\\") ||
                rel.Contains("/bin/") || rel.Contains("\\bin\\")) continue;

            var ext = Path.GetExtension(path).ToLowerInvariant();

            if (ext == ".dll" && !IsManagedAssembly(path))
            {
                findings.Add(new Finding(
                    Severity.Critical,
                    "native.unmanaged-dll",
                    "Unmanaged native DLL shipped inside package — opaque to scanner.",
                    rel,
                    FinderId: Id));
                continue;
            }

            if (NativeUnix.Contains(ext))
            {
                findings.Add(new Finding(
                    Severity.Critical,
                    "native.unix-shared-object",
                    $"Unmanaged Unix shared library ({ext}) in package.",
                    rel,
                    FinderId: Id));
                continue;
            }

            if (Executable.Contains(ext))
            {
                findings.Add(new Finding(
                    Severity.Critical,
                    "native.executable",
                    $"Standalone executable ({ext}) in package — highly suspicious.",
                    rel,
                    FinderId: Id));
            }
        }

        return Task.FromResult<IReadOnlyList<Finding>>(findings);
    }

    static string SafeRel(string root, string full)
    {
        try { return Path.GetRelativePath(root, full).Replace('\\', '/'); }
        catch { return full; }
    }

    // Cheap PE header sniff. Managed DLLs have a non-zero CLI directory in
    // the PE optional header; native DLLs do not.
    static bool IsManagedAssembly(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            using var br = new BinaryReader(fs);

            fs.Position = 0x3C;
            var peHeaderOffset = br.ReadInt32();
            if (peHeaderOffset <= 0 || peHeaderOffset > fs.Length - 4) return false;

            fs.Position = peHeaderOffset;
            if (br.ReadUInt32() != 0x00004550) return false; // "PE\0\0"

            fs.Position = peHeaderOffset + 4 + 20; // skip COFF header
            var magic = br.ReadUInt16();
            int cliDirOffset = peHeaderOffset + 4 + 20 + (magic == 0x20B ? 112 + 14 * 8 : 96 + 14 * 8);

            fs.Position = cliDirOffset;
            var rva = br.ReadUInt32();
            var size = br.ReadUInt32();
            return rva != 0 && size != 0;
        }
        catch { return false; }
    }
}
