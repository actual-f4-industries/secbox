namespace Secbox.Contracts;

public interface IRulePack
{
    RulePackInfo Info { get; }
    IReadOnlyList<Rule> Rules { get; }
}
