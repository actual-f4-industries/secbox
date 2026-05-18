using System.Collections.Concurrent;

namespace Secbox.Sentinel.Engine.Policy;

// Service-wide subscription book. Thread-safe; PipeClientSession adds/
// removes its own subscriptions, the dispatcher iterates over the current
// snapshot to fan events out. Caps total subscriptions per service to
// MaxSubscriptions as a coarse DoS guard.
public sealed class SubscriptionRegistry
{
    public int MaxSubscriptions { get; init; } = 32;

    readonly ConcurrentDictionary<string, Subscription> _subs = new();

    public bool TryAdd(Subscription s)
    {
        if (_subs.Count >= MaxSubscriptions) return false;
        return _subs.TryAdd(s.SubscriptionId, s);
    }

    public bool Remove(string id) => _subs.TryRemove(id, out _);

    public IReadOnlyCollection<Subscription> Snapshot() => _subs.Values.ToList();

    public int Count => _subs.Count;
}
