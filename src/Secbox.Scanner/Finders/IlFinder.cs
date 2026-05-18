using Mono.Cecil;
using Mono.Cecil.Cil;
using Secbox.Contracts;
using Secbox.Rules;
using Secbox.Rules.Packs;

namespace Secbox.Scanner.Finders;

// Deep Mono.Cecil-based IL walker. Goes beyond what MetadataFinder catches:
// individual IL instructions including ldstr literals (suspicious-string
// detection), ldftn / ldvirtftn (finalizer-reference trick), per-instruction
// generic instantiations, pinned local detection.
//
// Slower than MetadataFinder — opt-out via ScanOptions.IncludeIlWalk = false.
public sealed class IlFinder : IFinder
{
    public string Id => "il";
    public string Description => "Cecil-based IL instruction walker (deep analysis).";

    public bool AppliesTo(ScanTarget target) => target is AssemblyTarget or FolderTarget;

    public Task<IReadOnlyList<Finding>> ScanAsync(
        ScanTarget target,
        ScanContext context,
        CancellationToken ct = default)
    {
        var findings = new List<Finding>();
        if (!context.Options.IncludeIlWalk) return Task.FromResult<IReadOnlyList<Finding>>(findings);

        var compiledPacks = context.RulePacks.Select(p => new CompiledPack(p)).ToList();
        var engineMirror = EngineMirror.Build();

        if (target is AssemblyTarget a)
        {
            ScanFile(a.Path, a.Path, engineMirror, compiledPacks, findings, ct);
        }
        else if (target is FolderTarget f && Directory.Exists(f.Path))
        {
            foreach (var path in Directory.EnumerateFiles(f.Path, "*.dll", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                var rel = SafeRel(f.Path, path);
                if (rel.Contains("/obj/") || rel.Contains("\\obj\\") ||
                    rel.Contains("/bin/") || rel.Contains("\\bin\\")) continue;
                ScanFile(path, rel, engineMirror, compiledPacks, findings, ct);
            }
        }

        return Task.FromResult<IReadOnlyList<Finding>>(findings);
    }

    static string SafeRel(string root, string full)
    {
        try { return Path.GetRelativePath(root, full).Replace('\\', '/'); }
        catch { return full; }
    }

    void ScanFile(
        string path,
        string displayPath,
        RuleSet engineMirror,
        IReadOnlyList<CompiledPack> packs,
        List<Finding> sink,
        CancellationToken ct)
    {
        AssemblyDefinition? asm = null;
        try
        {
            // Tolerant resolver — Cecil's default throws AssemblyResolutionException
            // on missing references, and our scans target editor libraries that
            // reference engine DLLs we don't have on the search path. Throwing
            // thousands of exceptions per scan freezes the host. Swallow + return
            // null; MemberKey already handles unresolved refs by falling back to
            // signature-only keys.
            var resolver = new TolerantAssemblyResolver();
            resolver.AddSearchDirectory(Path.GetDirectoryName(path));
            var readerParams = new ReaderParameters
            {
                ReadingMode = ReadingMode.Immediate,
                InMemory = true,
                ReadSymbols = false,
                AssemblyResolver = resolver,
            };
            asm = AssemblyDefinition.ReadAssembly(path, readerParams);
        }
        catch (Exception ex)
        {
            sink.Add(new Finding(Severity.Medium, "il.read-failed",
                $"Could not read assembly: {ex.Message}", displayPath, FinderId: Id));
            return;
        }

        var localAsm = asm.Name.Name;
        var seen = new HashSet<string>();

        try
        {
            foreach (var module in asm.Modules)
            {
                foreach (var type in EnumerateTypes(module.Types))
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (var method in type.Methods)
                    {
                        if (!method.HasBody) continue;
                        ScanMethodBody(method, displayPath, localAsm, engineMirror, packs, seen, sink);
                    }
                }
            }
        }
        finally
        {
            asm.Dispose();
        }
    }

    static IEnumerable<TypeDefinition> EnumerateTypes(IEnumerable<TypeDefinition> types)
    {
        foreach (var t in types)
        {
            yield return t;
            if (t.HasNestedTypes)
                foreach (var nt in EnumerateTypes(t.NestedTypes))
                    yield return nt;
        }
    }

    // Returns null on resolution failure instead of throwing. Callers
    // (MemberKey.TryResolve etc.) already handle null gracefully.
    sealed class TolerantAssemblyResolver : DefaultAssemblyResolver
    {
        public override AssemblyDefinition? Resolve(AssemblyNameReference name)
        {
            try { return base.Resolve(name); } catch { return null; }
        }
        public override AssemblyDefinition? Resolve(AssemblyNameReference name, ReaderParameters parameters)
        {
            try { return base.Resolve(name, parameters); } catch { return null; }
        }
    }

    void ScanMethodBody(
        MethodDefinition method,
        string displayPath,
        string localAsm,
        RuleSet engineMirror,
        IReadOnlyList<CompiledPack> packs,
        HashSet<string> seen,
        List<Finding> sink)
    {
        var loc = $"{displayPath} :: {method.DeclaringType.FullName}::{method.Name}";

        // Pinned locals — unverifiable code, often paired with pointer arithmetic
        foreach (var v in method.Body.Variables)
        {
            if (v.IsPinned)
            {
                sink.Add(new Finding(Severity.High, "il.pinned-local",
                    "Pinned local variable — unverifiable code.", loc, FinderId: Id));
            }
        }

        foreach (var instr in method.Body.Instructions)
        {
            switch (instr.Operand)
            {
                case string s:
                    foreach (var needle in CriticalPack.SuspiciousStringLiterals)
                    {
                        if (s.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            sink.Add(new Finding(Severity.High, "il.suspicious-literal",
                                $"Literal contains \"{needle}\" — possible native-API target", loc, FinderId: Id));
                            break;
                        }
                    }
                    break;

                case MethodReference mref:
                    var asmName = MemberKey.AssemblyOf(mref);
                    if (asmName == localAsm) break;
                    var key = MemberKey.ForMethodRef(mref);
                    if (!seen.Add(key)) break;
                    Classify(key, asmName, loc, engineMirror, packs, sink);

                    // Finalizer-reference trick: ldftn/ldvirtftn of Finalize
                    if (mref.Name == "Finalize" &&
                        (instr.OpCode.Code == Code.Ldftn || instr.OpCode.Code == Code.Ldvirtftn))
                    {
                        sink.Add(new Finding(Severity.Critical, "il.finalizer-trick",
                            "Indirect reference to Finalize via ldftn/ldvirtftn — known exploit.",
                            loc, FinderId: Id));
                    }
                    break;

                case TypeReference tref:
                    var asmT = tref.Scope?.Name ?? "<unknown>";
                    if (asmT == localAsm) break;
                    var keyT = MemberKey.ForTypeRef(tref);
                    if (!seen.Add(keyT)) break;
                    Classify(keyT, asmT, loc, engineMirror, packs, sink);
                    break;
            }
        }
    }

    static void Classify(
        string key,
        string asmName,
        string location,
        RuleSet engineMirror,
        IReadOnlyList<CompiledPack> packs,
        List<Finding> sink)
    {
        foreach (var pack in packs)
        {
            var rule = pack.Match(key);
            if (rule != null)
            {
                sink.Add(new Finding(
                    rule.Severity,
                    rule.Id,
                    $"Hits {pack.PackId}: {key}",
                    location,
                    FixHint: rule.FixHint,
                    FinderId: "il"));
                return;
            }
        }

        if (engineMirror.IsAssemblyAllowed(asmName))
        {
            if (!engineMirror.IsAllowed(key))
            {
                sink.Add(new Finding(Severity.Medium, "engine.not-whitelisted",
                    $"Member not on engine game-side whitelist: {key}", location, FinderId: "il"));
            }
        }
        else
        {
            sink.Add(new Finding(Severity.Medium, "engine.foreign-assembly",
                $"Reference into non-whitelisted assembly: {asmName} ({key})", location, FinderId: "il"));
        }
    }
}
