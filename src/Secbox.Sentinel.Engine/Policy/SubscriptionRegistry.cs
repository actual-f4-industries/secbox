using System.Collections.Concurrent;

namespace Secbox.Sentinel.Engine.Policy;

// Service-wide subscription book. Thread-safe; PipeClientSession adds/
// removes its own subscriptions, the dispatcher iterates over the current
// snapshot to fan events out. Caps total subscriptions per service to
// MaxSubscriptions as a coarse DoS guard.
//
// Each TryAdd also calls ProcessTree.Watch so child processes spawned by
// that subscription's editor PID start being tracked. Remove() Unwatches
// when no remaining subscription still references that PID — protects
// against a leaked tracker entry when multiple editor instances share a
// PID space (which they don't on Windows, but the bookkeeping is cheap
// and the invariant is clearer).
public sealed class SubscriptionRegistry
{
    public int MaxSubscriptions { get; init; } = 32;

    readonly ConcurrentDictionary<string, Subscription> _subs = new();
    readonly ProcessTree _tree;

    public SubscriptionRegistry(ProcessTree tree)
    {
        _tree = tree;
    }

    public bool TryAdd(Subscription s)
    {
        if (_subs.Count >= MaxSubscriptions) return false;
        if (!_subs.TryAdd(s.SubscriptionId, s)) return false;
        _tree.Watch(s.EditorPid);
        return true;
    }

    public bool Remove(string id)
    {
        if (!_subs.TryRemove(id, out var removed)) return false;
        if (!_subs.Values.Any(s => s.EditorPid == removed.EditorPid))
            _tree.Unwatch(removed.EditorPid);
        return true;
    }

    public IReadOnlyCollection<Subscription> Snapshot() => _subs.Values.ToList();

    public int Count => _subs.Count;
}
