namespace Secbox.Sentinel.Contracts;

// Wire protocol version between Secbox.Sentinel.Client (in-editor) and
// Secbox.Sentinel.Service (the privileged Windows Service). Versioned
// independently from BridgeProtocol because the two surfaces evolve
// separately — the in-process bridge to Secbox.Core is one thing, the
// out-of-process pipe to Sentinel is another.
//
// Bump CurrentVersion on incompatible schema changes (renamed envelope
// fields, removed event kinds, changed enum semantics). Additive changes
// (new optional fields, new event kinds) keep the same version — clients
// must tolerate unknown fields and unknown KernelEventKind values.
public static class SentinelProtocol
{
    public const int CurrentVersion = 1;
    public const int MinSupportedVersion = 1;

    // Pipe name template. The {0} placeholder is the current user's SID so
    // each interactive user gets their own pipe and the service-side DACL
    // can scope by SID. Empty/missing SID falls back to "default".
    public const string PipeNameFormat = "secbox-sentinel-{0}";

    // Process / service registration constants — referenced by installer,
    // service host, and client so all three agree without duplication.
    public const string ServiceName = "SecboxSentinel";
    public const string ServiceDisplayName = "Secbox Sentinel";
    public const string ServiceDescription =
        "Provides kernel-level monitoring (file/process/network/registry) " +
        "for the s&box editor on behalf of the secbox library. Detection only; " +
        "all decisions remain in user-mode. Disable or uninstall to opt out.";
}
