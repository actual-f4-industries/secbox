using System.Text.Json;
using System.Text.Json.Serialization;
using Secbox.Contracts;
using Secbox.Rules.Packs;
using Secbox.Scanner.Pipeline;

namespace Secbox.Core;

// PUBLIC BRIDGE SURFACE. The editor adapter loads Secbox.Core.dll and
// reflectively invokes these static methods. Everything in/out is JSON
// to keep the bridge protocol decoupled from .NET type identity across
// AssemblyLoadContexts.
//
// Method names + signatures are pinned by BridgeProtocol constants — do not
// rename without bumping BridgeProtocol.CurrentVersion.
public static class SecboxApi
{
    static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    static readonly string BuildDateStamp =
        File.GetLastWriteTimeUtc(typeof(SecboxApi).Assembly.Location).ToString("O");

    /// <summary>Returns metadata about this loaded core for handshake/version checks.</summary>
    public static string GetInfo()
    {
        var info = new ApiInfo(
            ProtocolVersion: BridgeProtocol.CurrentVersion,
            ScannerVersion: typeof(SecboxApi).Assembly.GetName().Version?.ToString() ?? "0.0.0",
            AvailableFinders: FinderRegistry.All().Select(f => f.Id).ToList(),
            AvailableRulePacks: PackRegistry.All().Select(p => p.Info).ToList(),
            BuildDate: BuildDateStamp);
        return JsonSerializer.Serialize(info, JsonOpts);
    }

    /// <summary>Scan a folder. Returns JSON-serialized ScanReport.</summary>
    public static string ScanFolder(string folderPath, string? optionsJson)
        => RunScan(new FolderTarget(folderPath), optionsJson);

    /// <summary>Scan a single .NET assembly. Returns JSON-serialized ScanReport.</summary>
    public static string ScanAssembly(string dllPath, string? optionsJson)
        => RunScan(new AssemblyTarget(dllPath), optionsJson);

    /// <summary>Scan a single source file. Returns JSON-serialized ScanReport.</summary>
    public static string ScanSource(string sourcePath, string? optionsJson)
        => RunScan(new SourceTarget(sourcePath), optionsJson);

    static string RunScan(ScanTarget target, string? optionsJson)
    {
        ScanOptions? opts = null;
        Policy? policy = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(optionsJson))
            {
                var request = JsonSerializer.Deserialize<ScanRequest>(optionsJson, JsonOpts);
                opts = request?.Options;
                policy = request?.Policy;
            }
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(
                ErrorReport(target.Path, $"Invalid optionsJson: {ex.Message}"),
                JsonOpts);
        }

        try
        {
            var report = Bootstrap.DefaultPipeline
                .ScanAsync(target, opts, policy)
                .GetAwaiter()
                .GetResult();
            return JsonSerializer.Serialize(report, JsonOpts);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(
                ErrorReport(target.Path, $"Scan threw: {ex.Message}\n{ex.StackTrace}"),
                JsonOpts);
        }
    }

    static ScanReport ErrorReport(string target, string message) => new(
        Target: target,
        StartedAt: DateTimeOffset.UtcNow,
        CompletedAt: DateTimeOffset.UtcNow,
        Findings: new[] { new Finding(Severity.Critical, "core.scan-error", message, target) },
        RulePacksUsed: Array.Empty<RulePackInfo>(),
        ScannerVersion: typeof(SecboxApi).Assembly.GetName().Version?.ToString() ?? "0.0.0",
        ProtocolVersion: BridgeProtocol.CurrentVersion,
        Overall: Decision.Block);

    // Wire-format for the options arg — bundles ScanOptions + Policy so the
    // editor can pass both in one JSON payload.
    public sealed record ScanRequest(ScanOptions? Options, Policy? Policy);
}
