using System.Diagnostics;
using Secbox.Contracts;

namespace Secbox.Scanner.Pipeline;

// Orchestrates: dispatch every applicable finder over the target, dedupe,
// filter by severity, cap by MaxFindings, compute overall decision, build
// ScanReport.
public sealed class ScanPipeline : IPipeline
{
    readonly IReadOnlyList<IFinder> _finders;
    readonly IReadOnlyList<IRulePack> _rulePacks;
    readonly IDecisionEngine _decisionEngine;
    readonly string _scannerVersion;

    public ScanPipeline(
        IReadOnlyList<IFinder> finders,
        IReadOnlyList<IRulePack> rulePacks,
        IDecisionEngine? decisionEngine = null,
        string? scannerVersion = null)
    {
        _finders = finders;
        _rulePacks = rulePacks;
        _decisionEngine = decisionEngine ?? new DefaultDecisionEngine();
        _scannerVersion = scannerVersion ?? typeof(ScanPipeline).Assembly.GetName().Version?.ToString() ?? "0.0.0";
    }

    public async Task<ScanReport> ScanAsync(
        ScanTarget target,
        ScanOptions? options = null,
        Policy? policy = null,
        CancellationToken ct = default)
    {
        options ??= new ScanOptions();
        policy ??= new Policy();

        var startedAt = DateTimeOffset.UtcNow;
        var sw = Stopwatch.StartNew();

        var effectivePacks = options.RulePacksToRun is { Count: > 0 } restricted
            ? _rulePacks.Where(p => restricted.Contains(p.Info.Id)).ToList()
            : _rulePacks;

        var effectiveFinders = options.FindersToRun is { Count: > 0 } findersRestricted
            ? _finders.Where(f => findersRestricted.Contains(f.Id)).ToList()
            : _finders;

        var context = new ScanContext(options, policy, effectivePacks);

        var all = new List<Finding>();
        foreach (var finder in effectiveFinders)
        {
            ct.ThrowIfCancellationRequested();
            if (!finder.AppliesTo(target)) continue;

            try
            {
                var findings = await finder.ScanAsync(target, context, ct);
                all.AddRange(findings);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                all.Add(new Finding(
                    Severity.Low,
                    "pipeline.finder-threw",
                    $"Finder {finder.Id} threw: {ex.Message}",
                    target.Path,
                    FinderId: finder.Id));
            }
        }

        // Filter, dedupe, cap.
        var filtered = all.Where(f => f.Severity >= options.MinSeverity);
        var deduped = FindingDeduper.Dedupe(filtered);
        var capped = deduped.Count > options.MaxFindings
            ? deduped.Take(options.MaxFindings).ToList()
            : deduped;

        var overall = _decisionEngine.DecideOverall(capped, policy);
        var completed = DateTimeOffset.UtcNow;

        var packInfos = effectivePacks.Select(p => p.Info).ToList();

        return new ScanReport(
            Target: target.Path,
            StartedAt: startedAt,
            CompletedAt: completed,
            Findings: capped,
            RulePacksUsed: packInfos,
            ScannerVersion: _scannerVersion,
            ProtocolVersion: BridgeProtocol.CurrentVersion,
            Overall: overall);
    }
}
