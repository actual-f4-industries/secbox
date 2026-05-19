using System.Collections.Concurrent;

namespace Secbox.Sentinel.Engine.Policy;

// Tracks the live process-descendant set for each watched root PID
// (typically an editor's PID). Driven by ETW ProcessStart / ProcessStop
// events fed from the dispatcher BEFORE per-subscription matching.
//
// Why this exists: ETW kernel events carry a single PID. Without a
// descendant map, a subscription scoped to the editor's PID misses every
// kernel event done by spawned children — for example, when a library
// downloads scfu.exe and runs it, scfu.exe gets its own PID and its file/
// network/registry activity becomes invisible to the matcher.
//
// Tree-walk model is not used — we maintain explicit per-root descendant
// sets so matcher checks are O(1) (set membership). Each Watch(root) call
// seeds the set with the root PID itself. As children are spawned, we
// propagate: if a process's parent is in any watched set, add the child
// to that set too. Stop events remove the PID.
//
// Edge case: existing descendants at the time Watch() is called are NOT
// retroactively discovered — we'd need to enumerate live processes via
// the Win32 toolhelp snapshot, which has cross-thread cost and is rarely
// useful in practice (the editor's subscription is established within
// seconds of editor startup, before SCFU-style payloads have run). New
// children spawned after Watch() are caught correctly.
public sealed class ProcessTree
{
    // root pid -> set of pids in that root's descendant chain (inclusive).
    readonly ConcurrentDictionary<int, HashSet<int>> _byRoot = new();
    readonly Lock _gate = new();

    public void Watch(int rootPid)
    {
        if (rootPid <= 0) return;
        lock (_gate)
        {
            if (!_byRoot.ContainsKey(rootPid))
                _byRoot[rootPid] = new HashSet<int> { rootPid };
        }
    }

    public void Unwatch(int rootPid)
    {
        _byRoot.TryRemove(rootPid, out _);
    }

    public void OnProcessStart(int pid, int parentPid)
    {
        if (pid <= 0) return;
        lock (_gate)
        {
            foreach (var kv in _byRoot)
            {
                if (kv.Value.Contains(parentPid))
                    kv.Value.Add(pid);
            }
        }
    }

    public void OnProcessStop(int pid)
    {
        if (pid <= 0) return;
        lock (_gate)
        {
            foreach (var kv in _byRoot)
                kv.Value.Remove(pid);
        }
    }

    // True if `pid` is the root itself or a descendant. Used by the matcher
    // to decide whether an event should be considered for forwarding.
    public bool IsDescendantOrSelf(int pid, int rootPid)
    {
        if (rootPid == 0) return true; // unscoped subscription — accept everything
        if (pid == rootPid) return true;
        return _byRoot.TryGetValue(rootPid, out var set) && set.Contains(pid);
    }
}
