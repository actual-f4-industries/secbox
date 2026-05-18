using Secbox.Sentinel.Contracts;

namespace Secbox.Sentinel.Engine.Policy;

// Active per-client subscription state. Held by SubscriptionRegistry and
// consulted by the matcher for every event. Mutable counters (DroppedCount,
// LastDropReported) live on the subscription so backpressure notifications
// can summarize per-client without a separate stats table.
public sealed class Subscription
{
    public required string SubscriptionId { get; init; }
    public required int EditorPid { get; init; }
    public required ProviderKind Providers { get; init; }
    public bool CaptureStack { get; init; }
    public int MaxEventsPerSec { get; init; } = 5000;
    public IReadOnlyList<string>? PathAllowlist { get; init; }

    public long Forwarded;
    public long Dropped;
    public long LastDropReported;
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    public static Subscription From(SubscribeRequest r, int editorPid) => new()
    {
        SubscriptionId = r.SubscriptionId,
        EditorPid = editorPid,
        Providers = r.Providers,
        CaptureStack = r.CaptureStack,
        MaxEventsPerSec = r.MaxEventsPerSec,
        PathAllowlist = r.PathAllowlist,
    };
}
