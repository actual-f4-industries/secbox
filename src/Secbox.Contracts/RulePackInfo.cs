namespace Secbox.Contracts;

public sealed record RulePackInfo(
    string Id,
    string Version,
    string Source,
    string Description,
    int RuleCount);
