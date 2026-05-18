namespace Secbox.Contracts;

public sealed record Rule(
    string Id,
    Severity Severity,
    string Pattern,
    string? Rationale = null,
    string? FixHint = null,
    string? Category = null);
