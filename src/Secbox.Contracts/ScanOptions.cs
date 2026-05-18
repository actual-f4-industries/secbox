namespace Secbox.Contracts;

public sealed record ScanOptions(
    Severity MinSeverity = Severity.Low,
    int MaxFindings = 1000,
    IReadOnlyList<string>? FindersToRun = null,
    IReadOnlyList<string>? RulePacksToRun = null,
    bool IncludeIlWalk = true,
    bool IncludeSourceScan = true);
