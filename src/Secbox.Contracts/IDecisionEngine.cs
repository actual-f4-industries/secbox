namespace Secbox.Contracts;

public interface IDecisionEngine
{
    Decision DecideForFinding(Finding finding, Policy policy);
    Decision DecideOverall(IReadOnlyList<Finding> findings, Policy policy);
}
