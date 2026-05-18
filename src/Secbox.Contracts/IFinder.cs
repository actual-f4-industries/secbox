namespace Secbox.Contracts;

public interface IFinder
{
    string Id { get; }
    string Description { get; }
    bool AppliesTo(ScanTarget target);
    Task<IReadOnlyList<Finding>> ScanAsync(
        ScanTarget target,
        ScanContext context,
        CancellationToken ct = default);
}
