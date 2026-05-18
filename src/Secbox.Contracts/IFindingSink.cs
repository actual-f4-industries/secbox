namespace Secbox.Contracts;

public interface IFindingSink
{
    Task EmitAsync(Finding finding, CancellationToken ct = default);
    Task FlushAsync(CancellationToken ct = default);
}
