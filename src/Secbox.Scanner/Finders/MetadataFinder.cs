using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using Secbox.Contracts;
using Secbox.Rules;

namespace Secbox.Scanner.Finders;

// Fast metadata-table scanner using System.Reflection.Metadata (BCL — no
// extra deps). Walks AssemblyReferences, TypeReferences, MemberReferences,
// MethodDefinitions (for P/Invoke flag), CustomAttributes, TypeDefinitions
// (for ExplicitLayout). Cheap enough to run on every assembly during boot
// audit.
//
// Pairs with IlFinder: this catches metadata-table signals, IlFinder catches
// instruction-level signals (ldstr literals, opcode patterns).
public sealed class MetadataFinder : IFinder
{
    public string Id => "metadata";
    public string Description => "Fast metadata-table scan via System.Reflection.Metadata.";

    public bool AppliesTo(ScanTarget target) => target is AssemblyTarget or FolderTarget;

    public Task<IReadOnlyList<Finding>> ScanAsync(
        ScanTarget target,
        ScanContext context,
        CancellationToken ct = default)
    {
        var findings = new List<Finding>();
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
        if (!File.Exists(path)) return;

        FileStream? stream = null;
        PEReader? pe = null;
        try
        {
            stream = File.OpenRead(path);
            pe = new PEReader(stream);
            if (!pe.HasMetadata) return;
            var md = pe.GetMetadataReader();
            var localAsm = md.GetString(md.GetAssemblyDefinition().Name);

            var seen = new HashSet<string>();

            // Type references
            foreach (var handle in md.TypeReferences)
            {
                ct.ThrowIfCancellationRequested();
                var typeRef = md.GetTypeReference(handle);
                var ns = md.GetString(typeRef.Namespace);
                var name = md.GetString(typeRef.Name);
                var asmName = ResolveAssembly(md, typeRef.ResolutionScope);
                if (asmName == localAsm) continue;

                var key = string.IsNullOrEmpty(ns) ? $"{asmName}/{name}" : $"{asmName}/{ns}.{name}";
                if (!seen.Add(key)) continue;

                Classify(key, asmName, displayPath + " (typeref)", engineMirror, packs, sink);
            }

            // Member references
            foreach (var handle in md.MemberReferences)
            {
                ct.ThrowIfCancellationRequested();
                var memberRef = md.GetMemberReference(handle);
                var memberName = md.GetString(memberRef.Name);
                if (memberRef.Parent.Kind != HandleKind.TypeReference) continue;

                var parentRef = md.GetTypeReference((TypeReferenceHandle)memberRef.Parent);
                var ns = md.GetString(parentRef.Namespace);
                var typeName = md.GetString(parentRef.Name);
                var asmName = ResolveAssembly(md, parentRef.ResolutionScope);
                if (asmName == localAsm) continue;

                var typeKey = string.IsNullOrEmpty(ns) ? $"{asmName}/{typeName}" : $"{asmName}/{ns}.{typeName}";
                var key = $"{typeKey}.{memberName}";
                if (!seen.Add(key)) continue;

                Classify(key, asmName, displayPath + " (memberref)", engineMirror, packs, sink);
            }

            // P/Invoke methods — detected via flag, not attribute resolution
            foreach (var handle in md.MethodDefinitions)
            {
                ct.ThrowIfCancellationRequested();
                var methodDef = md.GetMethodDefinition(handle);
                if ((methodDef.Attributes & MethodAttributes.PinvokeImpl) == 0) continue;

                var typeDef = md.GetTypeDefinition(methodDef.GetDeclaringType());
                var typeFqn = $"{md.GetString(typeDef.Namespace)}.{md.GetString(typeDef.Name)}";
                var methodName = md.GetString(methodDef.Name);

                string target = "(unresolved)";
                try
                {
                    var importInfo = methodDef.GetImport();
                    if (!importInfo.Module.IsNil)
                    {
                        var mod = md.GetModuleReference(importInfo.Module);
                        var entry = importInfo.Name.IsNil ? methodName : md.GetString(importInfo.Name);
                        target = $"{md.GetString(mod.Name)}!{entry}";
                    }
                }
                catch { }

                sink.Add(new Finding(
                    Severity.Critical,
                    "metadata.pinvoke",
                    $"P/Invoke to native code: {target}",
                    $"{displayPath} :: {typeFqn}::{methodName}",
                    FinderId: Id));
            }

            // Critical attributes (via constructor's declaring type)
            foreach (var handle in md.CustomAttributes)
            {
                ct.ThrowIfCancellationRequested();
                var ca = md.GetCustomAttribute(handle);
                var attrKey = ResolveAttributeTypeKey(md, ca.Constructor);
                if (attrKey == null) continue;

                foreach (var pack in packs)
                {
                    var rule = pack.Match(attrKey);
                    if (rule != null)
                    {
                        sink.Add(new Finding(
                            rule.Severity,
                            rule.Id,
                            $"Critical attribute: {attrKey}",
                            $"{displayPath} (custom attribute)",
                            FixHint: rule.FixHint,
                            FinderId: Id));
                        break;
                    }
                }
            }

            // ExplicitLayout types
            foreach (var handle in md.TypeDefinitions)
            {
                ct.ThrowIfCancellationRequested();
                var typeDef = md.GetTypeDefinition(handle);
                if ((typeDef.Attributes & TypeAttributes.ExplicitLayout) == 0) continue;

                var name = md.GetString(typeDef.Name);
                if (name.StartsWith("__StaticArrayInitTypeSize=")) continue;

                var ns = md.GetString(typeDef.Namespace);
                var fqn = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
                sink.Add(new Finding(
                    Severity.High,
                    "metadata.explicit-layout",
                    "ExplicitLayout type — can alias memory, often paired with marshalling.",
                    $"{displayPath} :: {fqn}",
                    FinderId: Id));
            }
        }
        catch (Exception ex)
        {
            sink.Add(new Finding(Severity.Medium, "metadata.read-failed",
                $"Could not read assembly: {ex.Message}", displayPath, FinderId: Id));
        }
        finally
        {
            pe?.Dispose();
            stream?.Dispose();
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
        // Denylists win — Critical (or whatever the rule severity is) regardless
        // of engine whitelist.
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
                    FinderId: "metadata"));
                return;
            }
        }

        // Engine-mirror allowlist check.
        if (engineMirror.IsAssemblyAllowed(asmName))
        {
            if (!engineMirror.IsAllowed(key))
            {
                sink.Add(new Finding(
                    Severity.Medium,
                    "engine.not-whitelisted",
                    $"Member not on engine game-side whitelist: {key}",
                    location,
                    FinderId: "metadata"));
            }
        }
        else
        {
            sink.Add(new Finding(
                Severity.Medium,
                "engine.foreign-assembly",
                $"Reference into non-whitelisted assembly: {asmName} ({key})",
                location,
                FinderId: "metadata"));
        }
    }

    static string ResolveAssembly(MetadataReader md, EntityHandle scope)
    {
        switch (scope.Kind)
        {
            case HandleKind.AssemblyReference:
                return md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)scope).Name);
            case HandleKind.ModuleReference:
                return md.GetString(md.GetModuleReference((ModuleReferenceHandle)scope).Name);
            case HandleKind.TypeReference:
                var nested = md.GetTypeReference((TypeReferenceHandle)scope);
                return ResolveAssembly(md, nested.ResolutionScope);
            case HandleKind.AssemblyDefinition:
                return md.GetString(md.GetAssemblyDefinition().Name);
            default:
                return "<unknown>";
        }
    }

    static string? ResolveAttributeTypeKey(MetadataReader md, EntityHandle ctorHandle)
    {
        switch (ctorHandle.Kind)
        {
            case HandleKind.MemberReference:
                var mref = md.GetMemberReference((MemberReferenceHandle)ctorHandle);
                if (mref.Parent.Kind != HandleKind.TypeReference) return null;
                var parent = md.GetTypeReference((TypeReferenceHandle)mref.Parent);
                var ns = md.GetString(parent.Namespace);
                var name = md.GetString(parent.Name);
                var asmName = ResolveAssembly(md, parent.ResolutionScope);
                return string.IsNullOrEmpty(ns) ? $"{asmName}/{name}" : $"{asmName}/{ns}.{name}";
            case HandleKind.MethodDefinition:
                var mdef = md.GetMethodDefinition((MethodDefinitionHandle)ctorHandle);
                var typeDef = md.GetTypeDefinition(mdef.GetDeclaringType());
                var tns = md.GetString(typeDef.Namespace);
                var tn = md.GetString(typeDef.Name);
                var localAsm = md.GetString(md.GetAssemblyDefinition().Name);
                return string.IsNullOrEmpty(tns) ? $"{localAsm}/{tn}" : $"{localAsm}/{tns}.{tn}";
            default:
                return null;
        }
    }
}
