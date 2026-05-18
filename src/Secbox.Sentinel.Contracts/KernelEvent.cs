namespace Secbox.Sentinel.Contracts;

// Normalized kernel event delivered to subscribers. JSON-serializable,
// camelCase on the wire. Path/Target semantics depend on Kind:
//   FileXxx       → Path is the filesystem path
//   ProcessStart  → Path is the spawned image path, Extras["commandLine"]
//   ImageLoad     → Path is the loaded module path
//   NetXxx        → Target is "host:port" or IP literal
//   RegXxx        → Path is the registry key path, Extras["value"] / ["data"]
public sealed record KernelEvent(
    long Sequence,
    KernelEventKind Kind,
    DateTimeOffset Timestamp,
    int Pid,
    int Tid,
    string? Path,
    string? Target,
    IReadOnlyDictionary<string, string>? Extras,
    IReadOnlyList<StackFrame>? UserStack);

public sealed record StackFrame(
    string Module,
    long Offset,
    string? Symbol = null);
