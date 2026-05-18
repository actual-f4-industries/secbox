namespace Secbox.Contracts;

public interface IPipeline
{
    Task<ScanReport> ScanAsync(
        ScanTarget target,
        ScanOptions? options = null,
        Policy? policy = null,
        CancellationToken ct = default);
}
