using System.Text.Json.Serialization;

namespace Secbox.Sentinel.Contracts;

// Discriminated-union envelope used in both directions on the pipe. One
// JSON object per line. The `type` field selects which payload field is
// populated. Unknown types are skipped (forward-compat).
public sealed class EventEnvelope
{
    [JsonPropertyName("type")] public string Type { get; set; } = "";

    // --- Client → Service ---
    public HelloRequest? Hello { get; set; }
    public SubscribeRequest? Subscribe { get; set; }
    public UnsubscribeRequest? Unsubscribe { get; set; }
    public PingMessage? Ping { get; set; }

    // --- Service → Client ---
    public HelloAck? HelloAck { get; set; }
    public SubscribeAck? SubscribeAck { get; set; }
    public KernelEvent? Event { get; set; }
    public BackpressureNotice? Backpressure { get; set; }
    public ErrorMessage? Error { get; set; }
    public PongMessage? Pong { get; set; }

    public static class Types
    {
        public const string Hello = "hello";
        public const string HelloAck = "hello-ack";
        public const string Subscribe = "subscribe";
        public const string SubscribeAck = "subscribe-ack";
        public const string Unsubscribe = "unsubscribe";
        public const string Event = "event";
        public const string Backpressure = "backpressure";
        public const string Error = "error";
        public const string Ping = "ping";
        public const string Pong = "pong";
    }
}

public sealed record HelloRequest(
    int ClientProtocolVersion,
    string ClientBuild,
    int EditorPid,
    string Nonce);

public sealed record HelloAck(
    int ServerProtocolVersion,
    string ServerBuild,
    string Challenge,
    bool Authenticated);

public sealed record SubscribeRequest(
    string SubscriptionId,
    ProviderKind Providers,
    bool CaptureStack = false,
    int MaxEventsPerSec = 5000,
    IReadOnlyList<string>? PathAllowlist = null);

public sealed record SubscribeAck(
    string SubscriptionId,
    ProviderKind GrantedProviders,
    string? RejectionReason = null);

public sealed record UnsubscribeRequest(
    string SubscriptionId);

public sealed record BackpressureNotice(
    string SubscriptionId,
    long DroppedSinceLast,
    long TotalDropped);

public sealed record ErrorMessage(
    string Code,
    string Message);

public sealed record PingMessage(DateTimeOffset Timestamp);
public sealed record PongMessage(DateTimeOffset Timestamp);

public static class ErrorCodes
{
    public const string ProtocolMismatch = "protocol-mismatch";
    public const string AuthFailed = "auth-failed";
    public const string PermissionDenied = "permission-denied";
    public const string UnknownSubscription = "unknown-subscription";
    public const string ProviderUnavailable = "provider-unavailable";
    public const string Internal = "internal-error";
}
