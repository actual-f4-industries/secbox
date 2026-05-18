namespace Secbox.Sentinel.Client;

// Exponential backoff with jitter for pipe reconnects. Caps at MaxDelay so
// a long outage doesn't push retries into multi-minute territory.
public sealed class ReconnectPolicy
{
    public TimeSpan InitialDelay { get; init; } = TimeSpan.FromMilliseconds(250);
    public TimeSpan MaxDelay { get; init; } = TimeSpan.FromSeconds(30);
    public double Multiplier { get; init; } = 2.0;
    public int MaxAttempts { get; init; } = 0;  // 0 = unbounded

    int _attempt;
    readonly Random _rng = new();

    public TimeSpan NextDelay()
    {
        _attempt++;
        var pure = InitialDelay.TotalMilliseconds * Math.Pow(Multiplier, _attempt - 1);
        var capped = Math.Min(pure, MaxDelay.TotalMilliseconds);
        // ±20% jitter so a herd of clients doesn't reconnect in lock-step.
        var jitter = 1.0 + (_rng.NextDouble() - 0.5) * 0.4;
        return TimeSpan.FromMilliseconds(capped * jitter);
    }

    public bool ShouldRetry => MaxAttempts == 0 || _attempt < MaxAttempts;

    public void Reset() => _attempt = 0;
}
