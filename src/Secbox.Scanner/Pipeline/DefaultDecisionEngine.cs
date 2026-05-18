using Secbox.Contracts;

namespace Secbox.Scanner.Pipeline;

// Default policy → decision translator.
//
// Per-finding decision:
//   - in policy's allowlist     → AllowOnce
//   - in policy's blocklist     → Block
//   - Critical + BlockCritical  → Block
//   - >= PromptThreshold        → Unreviewed (UI must prompt)
//   - below threshold           → AllowOnce
//
// Overall decision = worst of all individual decisions (Block > Quarantine >
// Unreviewed > AllowOnce > TrustAlways).
public sealed class DefaultDecisionEngine : IDecisionEngine
{
    public Decision DecideForFinding(Finding finding, Policy policy)
    {
        if (policy.RuleBlocklist?.Contains(finding.RuleId) == true)
            return Decision.Block;

        if (policy.RuleAllowlist?.Contains(finding.RuleId) == true)
            return Decision.AllowOnce;

        if (finding.Severity == Severity.Critical && policy.BlockCriticalByDefault)
            return Decision.Block;

        if (finding.Severity >= policy.PromptThreshold)
            return Decision.Unreviewed;

        return Decision.AllowOnce;
    }

    public Decision DecideOverall(IReadOnlyList<Finding> findings, Policy policy)
    {
        if (findings.Count == 0) return Decision.AllowOnce;

        var worst = Decision.AllowOnce;
        foreach (var f in findings)
        {
            var d = DecideForFinding(f, policy);
            if (Rank(d) > Rank(worst)) worst = d;
        }
        return worst;
    }

    static int Rank(Decision d) => d switch
    {
        Decision.Block => 4,
        Decision.Quarantine => 3,
        Decision.Unreviewed => 2,
        Decision.AllowOnce => 1,
        Decision.TrustAlways => 0,
        _ => 0,
    };
}
