using System.Diagnostics;

namespace Secbox.Core.RuntimeSensors;

// Per-thread ring of recent managed call attributions. A Tier-E (Harmony)
// prefix records an entry just before a tripwire method runs; the
// EventCorrelator looks up entries within a short time window when a Tier-A
// kernel event fires for the same TID, allowing attribution of an OS-level
// operation back to a specific library frame.
//
// Lock-free single-writer-per-TID, multi-reader. Bounded; entries time-decay
// after MaxAgeMs.
public static class CallAttributionRing
{
    public const int SlotsPerThread = 16;
    public const long MaxAgeTicks = TimeSpan.TicksPerMillisecond * 200;

    public sealed class Entry
    {
        public long TimestampTicks;
        public int ManagedTid;
        public int NativeTid;
        public string? CallerAssembly;
        public string? CallerMethod;
        public string? Op;
        public string? ArgsSummary;
    }

    static readonly System.Collections.Concurrent.ConcurrentDictionary<int, Entry[]> _byThread = new();
    static readonly System.Collections.Concurrent.ConcurrentDictionary<int, int> _cursor = new();

    public static void Record(Entry e)
    {
        if (e.ManagedTid == 0) e.ManagedTid = Environment.CurrentManagedThreadId;
        var slots = _byThread.GetOrAdd(e.ManagedTid, _ => new Entry[SlotsPerThread]);
        var idx = (_cursor.AddOrUpdate(e.ManagedTid, 0, (_, v) => v + 1)) % SlotsPerThread;
        slots[idx] = e;
    }

    // Lookup: matching entry on the given thread (managed OR native) within
    // ±windowMs of the given timestamp. Returns null if no plausible match.
    public static Entry? Lookup(int managedTid, int nativeTid, DateTimeOffset at, int windowMs = 50)
    {
        var nowTicks = at.UtcTicks;
        var windowTicks = TimeSpan.TicksPerMillisecond * windowMs;

        Entry? best = null;
        long bestDelta = long.MaxValue;

        if (managedTid != 0 && _byThread.TryGetValue(managedTid, out var slots))
            ScanSlots(slots, nowTicks, windowTicks, ref best, ref bestDelta);

        if (nativeTid != 0)
        {
            foreach (var kvp in _byThread)
            {
                ScanSlotsForNativeTid(kvp.Value, nativeTid, nowTicks, windowTicks, ref best, ref bestDelta);
            }
        }

        return best;
    }

    static void ScanSlots(Entry[] slots, long nowTicks, long windowTicks, ref Entry? best, ref long bestDelta)
    {
        for (int i = 0; i < slots.Length; i++)
        {
            var e = slots[i];
            if (e == null) continue;
            var delta = Math.Abs(nowTicks - e.TimestampTicks);
            if (delta > windowTicks) continue;
            if (delta < bestDelta) { best = e; bestDelta = delta; }
        }
    }

    static void ScanSlotsForNativeTid(Entry[] slots, int nativeTid, long nowTicks, long windowTicks, ref Entry? best, ref long bestDelta)
    {
        for (int i = 0; i < slots.Length; i++)
        {
            var e = slots[i];
            if (e == null || e.NativeTid != nativeTid) continue;
            var delta = Math.Abs(nowTicks - e.TimestampTicks);
            if (delta > windowTicks) continue;
            if (delta < bestDelta) { best = e; bestDelta = delta; }
        }
    }

    public static long NowTicks() => DateTimeOffset.UtcNow.UtcTicks;
}
