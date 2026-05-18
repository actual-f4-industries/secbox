namespace Secbox.Contracts;

public sealed record Finding(
    Severity Severity,
    string RuleId,
    string Message,
    string Location,
    string? Evidence = null,
    string? FixHint = null,
    string? FinderId = null)
{
    public override string ToString() =>
        $"[{Severity}] {RuleId} @ {Location}: {Message}";
}
