namespace Secbox.Contracts;

public sealed record Policy(
    Severity PromptThreshold = Severity.Medium,
    bool BlockCriticalByDefault = true,
    bool BlockUnmanagedDlls = true,
    IReadOnlySet<string>? RuleAllowlist = null,
    IReadOnlySet<string>? RuleBlocklist = null);
