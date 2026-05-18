using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Secbox.Contracts;
using Secbox.Rules.Packs;

namespace Secbox.Scanner.Finders;

// Roslyn syntax-walker source scanner. Catches suspect using directives,
// critical attribute usage, dangerous identifier names, and suspicious string
// literals. Binary scanner is authoritative; source findings are triage to
// surface issues in packages that ship source.
public sealed class SourceFinder : IFinder
{
    public string Id => "source";
    public string Description => "Roslyn syntax walker over .cs files for suspect patterns.";

    public bool AppliesTo(ScanTarget target) => target is SourceTarget or FolderTarget;

    public async Task<IReadOnlyList<Finding>> ScanAsync(
        ScanTarget target,
        ScanContext context,
        CancellationToken ct = default)
    {
        if (!context.Options.IncludeSourceScan) return Array.Empty<Finding>();

        var findings = new List<Finding>();

        if (target is SourceTarget s)
        {
            await ScanFileAsync(s.Path, s.Path, findings, ct);
        }
        else if (target is FolderTarget f && Directory.Exists(f.Path))
        {
            foreach (var path in Directory.EnumerateFiles(f.Path, "*.cs", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                var rel = SafeRel(f.Path, path);
                if (rel.Contains("/obj/") || rel.Contains("\\obj\\") ||
                    rel.Contains("/bin/") || rel.Contains("\\bin\\")) continue;
                await ScanFileAsync(path, rel, findings, ct);
            }
        }

        return findings;
    }

    static readonly string[] SuspectNamespaces =
    {
        "System.IO",
        "System.Diagnostics",
        "System.Runtime.InteropServices",
        "System.Reflection.Emit",
        "System.Runtime.Loader",
        "System.Net.Sockets",
        "Microsoft.Win32",
        "Microsoft.CodeAnalysis.CSharp.Scripting",
        "Microsoft.CodeAnalysis.Scripting",
    };

    static readonly string[] CriticalIdentifiers =
    {
        "DllImport", "LibraryImport", "UnsafeAccessor",
        "Process", "ProcessStartInfo",
        "AssemblyLoadContext",
        "LoadFile", "LoadFrom", "UnsafeLoadFrom",
        "GetDelegateForFunctionPointer", "GetFunctionPointerForDelegate",
        "NativeLibrary",
        "CSharpScript", "ScriptOptions",
    };

    static readonly string[] HighIdentifiers =
    {
        "File", "Directory", "DirectoryInfo", "FileInfo", "FileStream",
        "FileSystemWatcher", "DriveInfo", "IsolatedStorage",
        "WebClient", "WebRequest", "HttpListener", "TcpClient", "UdpClient",
        "Socket", "Dns",
        "Registry", "RegistryKey",
        "Activator",
        "MethodInfo", "ConstructorInfo", "FieldInfo", "PropertyInfo",
    };

    static async Task ScanFileAsync(string path, string displayPath, List<Finding> sink, CancellationToken ct)
    {
        string text;
        try { text = await File.ReadAllTextAsync(path, ct); }
        catch (Exception ex)
        {
            sink.Add(new Finding(Severity.Low, "source.read-failed",
                $"Could not read source: {ex.Message}", displayPath, FinderId: "source"));
            return;
        }

        SyntaxTree tree;
        try { tree = CSharpSyntaxTree.ParseText(text, path: path, cancellationToken: ct); }
        catch (Exception ex)
        {
            sink.Add(new Finding(Severity.Low, "source.parse-failed",
                $"Could not parse: {ex.Message}", displayPath, FinderId: "source"));
            return;
        }

        var walker = new Walker(displayPath, sink);
        walker.Visit(await tree.GetRootAsync(ct));
    }

    static string SafeRel(string root, string full)
    {
        try { return Path.GetRelativePath(root, full).Replace('\\', '/'); }
        catch { return full; }
    }

    sealed class Walker : CSharpSyntaxWalker
    {
        readonly string _path;
        readonly List<Finding> _sink;

        public Walker(string path, List<Finding> sink) : base(SyntaxWalkerDepth.Node)
        {
            _path = path;
            _sink = sink;
        }

        string LocAt(SyntaxNode n)
        {
            var span = n.GetLocation().GetLineSpan();
            return $"{_path}:{span.StartLinePosition.Line + 1}";
        }

        public override void VisitUsingDirective(UsingDirectiveSyntax node)
        {
            var name = node.Name?.ToString();
            if (name != null)
            {
                foreach (var ns in SuspectNamespaces)
                {
                    if (name == ns || name.StartsWith(ns + "."))
                    {
                        _sink.Add(new Finding(Severity.Low, "source.suspect-using",
                            $"Imports suspect namespace: {name}", LocAt(node), FinderId: "source"));
                        break;
                    }
                }
            }
            base.VisitUsingDirective(node);
        }

        public override void VisitAttribute(AttributeSyntax node)
        {
            var name = node.Name?.ToString() ?? "";
            foreach (var crit in CriticalIdentifiers)
            {
                if (name == crit || name.EndsWith("." + crit))
                {
                    _sink.Add(new Finding(Severity.Critical, "source.critical-attr",
                        $"Attribute usage: [{name}] — strong attack signal", LocAt(node), FinderId: "source"));
                    break;
                }
            }
            base.VisitAttribute(node);
        }

        public override void VisitIdentifierName(IdentifierNameSyntax node)
        {
            var ident = node.Identifier.ValueText;
            foreach (var crit in CriticalIdentifiers)
            {
                if (ident == crit)
                {
                    _sink.Add(new Finding(Severity.Critical, "source.critical-ident",
                        $"Identifier reference: {ident}", LocAt(node), FinderId: "source"));
                    break;
                }
            }
            foreach (var high in HighIdentifiers)
            {
                if (ident == high)
                {
                    _sink.Add(new Finding(Severity.High, "source.high-ident",
                        $"Identifier reference: {ident} — verify in binary scan", LocAt(node), FinderId: "source"));
                    break;
                }
            }
            base.VisitIdentifierName(node);
        }

        public override void VisitLiteralExpression(LiteralExpressionSyntax node)
        {
            if (node.IsKind(SyntaxKind.StringLiteralExpression))
            {
                var s = node.Token.ValueText ?? "";
                foreach (var needle in CriticalPack.SuspiciousStringLiterals)
                {
                    if (s.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        _sink.Add(new Finding(Severity.High, "source.suspicious-literal",
                            $"String literal contains \"{needle}\"", LocAt(node), FinderId: "source"));
                        break;
                    }
                }
            }
            base.VisitLiteralExpression(node);
        }
    }
}
