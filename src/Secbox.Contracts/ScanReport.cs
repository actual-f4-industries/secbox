namespace Secbox.Contracts;

public sealed record ScanReport(
    string Target,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<RulePackInfo> RulePacksUsed,
    string ScannerVersion,
    int ProtocolVersion,
    Decision Overall = Decision.Unreviewed);
