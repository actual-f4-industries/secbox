using Secbox.Contracts;

namespace Secbox.Rules.Packs;

// Encodes policy for unmanaged binaries shipped inside a managed-library
// package. Native code is opaque to .NET-IL scanners, so we treat any
// presence of unmanaged binaries as a Critical signal that requires an
// explicit user decision.
//
// This pack is mostly documentation — the actual detection logic lives in
// NativeBinaryFinder, which checks file extensions and the PE header. The
// rule entries exist so reports / decision engines can reference them by Id.
public sealed class NativeBinaryPack : IRulePack
{
    public const string PackId = "native-binary.v1";
    public const string PackVersion = "1.0.0";

    public RulePackInfo Info { get; }
    public IReadOnlyList<Rule> Rules { get; }

    public NativeBinaryPack()
    {
        Rules = new[]
        {
            new Rule(
                Id: "native.unmanaged-dll",
                Severity: Severity.Critical,
                Pattern: "*.dll (unmanaged)",
                Rationale: "Unmanaged native DLL inside package — opaque to IL scanner.",
                FixHint: "Replace with managed implementation, or split into a clearly-marked native dependency users opt into.",
                Category: "native"),
            new Rule(
                Id: "native.unix-shared-object",
                Severity: Severity.Critical,
                Pattern: "*.so / *.dylib",
                Rationale: "Unix unmanaged shared library — opaque to IL scanner.",
                Category: "native"),
            new Rule(
                Id: "native.executable",
                Severity: Severity.Critical,
                Pattern: "*.exe / *.bat / *.ps1 / *.sh",
                Rationale: "Standalone executable shipped inside a managed library — extremely suspicious.",
                Category: "native"),
        };

        Info = new RulePackInfo(
            Id: PackId,
            Version: PackVersion,
            Source: "Secbox.Rules.Packs.NativeBinaryPack",
            Description: "Policy for unmanaged binaries inside library packages.",
            RuleCount: Rules.Count);
    }
}
