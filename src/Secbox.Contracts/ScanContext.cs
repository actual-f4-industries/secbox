namespace Secbox.Contracts;

public sealed class ScanContext
{
    public ScanContext(ScanOptions options, Policy policy, IReadOnlyList<IRulePack> rulePacks)
    {
        Options = options;
        Policy = policy;
        RulePacks = rulePacks;
    }

    public ScanOptions Options { get; }
    public Policy Policy { get; }
    public IReadOnlyList<IRulePack> RulePacks { get; }
}
