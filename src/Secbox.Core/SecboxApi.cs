using System.Text.Json;
using System.Text.Json.Serialization;
using Secbox.Contracts;
using Secbox.Core.RuntimeSensors;
using Secbox.Core.RuntimeSensors.Sensors;
using Secbox.Core.RuntimeSensors.Sinks;
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

    // ============================================================
    // Runtime sensors (BridgeProtocol v2)
    //
    // The adapter calls AttachRuntimeSensors once after EnsureReady.
    // Returns a sensor-attach result JSON with per-sensor status. Events
    // flow back through `eventSink` as JSON lines (one finding per call).
    // ============================================================

    static SensorRegistry? _runtimeSensors;
    static readonly object _runtimeLock = new();

    /// <summary>
    /// Attach runtime sensors (Tier B profiler always; Tier A ETW iff
    /// options say so). `eventSink` receives JSON-line AttributedFinding
    /// payloads asynchronously.
    /// </summary>
    public static string AttachRuntimeSensors(string optionsJson, Action<string> eventSink)
    {
        try
        {
            var opts = string.IsNullOrWhiteSpace(optionsJson)
                ? new RuntimeSensorOptions(EnableProfiler: true, EnableEtw: false)
                : JsonSerializer.Deserialize<RuntimeSensorOptions>(optionsJson, JsonOpts)
                    ?? new RuntimeSensorOptions(true, false);

            lock (_runtimeLock)
            {
                if (_runtimeSensors != null)
                    return JsonSerializer.Serialize(new RuntimeSensorAttachResult(
                        Attached: false,
                        Message: "Runtime sensors already attached. Detach first.",
                        Sensors: GetStatusSnapshot()), JsonOpts);

                _runtimeSensors = new SensorRegistry();
                _runtimeSensors.Correlator.AddSink(new JsonLineSink(eventSink));

                if (opts.EnableProfiler)
                    _runtimeSensors.Add(new ProfilerSensor());
                if (opts.EnableEtw)
                    _runtimeSensors.Add(new EtwSensor());
            }

            var sensorOpts = new SensorOptions(
                EditorPid: Environment.ProcessId,
                Desired: opts.DesiredCapabilities,
                PathAllowlist: opts.PathAllowlist,
                CaptureStack: opts.CaptureStack);

            _runtimeSensors.StartAllAsync(sensorOpts, CancellationToken.None)
                .GetAwaiter().GetResult();

            return JsonSerializer.Serialize(new RuntimeSensorAttachResult(
                Attached: true,
                Message: null,
                Sensors: GetStatusSnapshot()), JsonOpts);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new RuntimeSensorAttachResult(
                Attached: false,
                Message: $"Attach failed: {ex.Message}",
                Sensors: Array.Empty<SensorStatusInfo>()), JsonOpts);
        }
    }

    /// <summary>Detach all running sensors.</summary>
    public static string DetachRuntimeSensors()
    {
        SensorRegistry? registry;
        lock (_runtimeLock) { registry = _runtimeSensors; _runtimeSensors = null; }
        if (registry == null) return "{\"detached\":false,\"reason\":\"not attached\"}";

        try { registry.StopAllAsync(CancellationToken.None).GetAwaiter().GetResult(); }
        catch { }
        try { registry.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
        catch { }
        return "{\"detached\":true}";
    }

    /// <summary>Snapshot of every registered sensor's current state.</summary>
    public static string GetSensorStatus()
        => JsonSerializer.Serialize(GetStatusSnapshot(), JsonOpts);

    static IReadOnlyList<SensorStatusInfo> GetStatusSnapshot()
    {
        var reg = _runtimeSensors;
        if (reg == null) return Array.Empty<SensorStatusInfo>();
        return reg.Sensors.Select(s => new SensorStatusInfo(
            Id: s.Id,
            Status: s.Status.ToString(),
            Capabilities: (int)s.Capabilities,
            LastError: s.LastError)).ToList();
    }

    public sealed record RuntimeSensorOptions(
        bool EnableProfiler = true,
        bool EnableEtw = false,
        SensorCapabilities DesiredCapabilities = SensorCapabilities.ManagedCalls
            | SensorCapabilities.DynamicCode
            | SensorCapabilities.KernelFile
            | SensorCapabilities.KernelProcess
            | SensorCapabilities.KernelNetwork
            | SensorCapabilities.NativeImageLoad,
        bool CaptureStack = false,
        IReadOnlyList<string>? PathAllowlist = null);

    public sealed record RuntimeSensorAttachResult(
        bool Attached,
        string? Message,
        IReadOnlyList<SensorStatusInfo> Sensors);

    public sealed record SensorStatusInfo(
        string Id,
        string Status,
        int Capabilities,
        string? LastError);
}
