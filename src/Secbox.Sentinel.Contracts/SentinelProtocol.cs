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

    // Fixed pipe name. A previous design embedded the current user's SID to
    // give each interactive user a dedicated pipe — that doesn't work when
    // the service runs as LocalSystem, because the service-side resolver
    // would produce a pipe named after S-1-5-18 while clients (running as
    // the interactive user) would look for a pipe named after their own
    // SID. They never met.
    //
    // Security is enforced by:
    //   1. PipeSecurity DACL — Interactive + SYSTEM only, no remote.
    //   2. ClientAuthenticator — per-connection process validation
    //      (image path, signature, optional PID match).
    public const string PipeName = "secbox-sentinel";

    // Process / service registration constants — referenced by installer,
    // service host, and client so all three agree without duplication.
    public const string ServiceName = "SecboxSentinel";
    public const string ServiceDisplayName = "Secbox Sentinel";
    public const string ServiceDescription =
        "Provides kernel-level monitoring (file/process/network/registry) " +
        "for the s&box editor on behalf of the secbox library. Detection only; " +
        "all decisions remain in user-mode. Disable or uninstall to opt out.";
}
