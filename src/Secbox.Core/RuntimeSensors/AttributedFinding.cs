using Secbox.Contracts;

namespace Secbox.Core.RuntimeSensors;

// What the EventCorrelator emits. A SensorEvent enriched with caller
// attribution (when available) and a Severity decided by the policy layer.
//
// Doubles as the JSON payload pushed to the in-editor adapter via the
// bridge's eventSink callback.
public sealed record AttributedFinding(
    long Sequence,
    DateTimeOffset Timestamp,
    SensorEventKind Kind,
    Severity Severity,
    IReadOnlyList<string> SensorIds,    // 1+ — multi-sensor dedupes accumulate ids
    int Pid,
    int Tid,
    string? Target,
    string? CallerAssembly,
    string? CallerMethod,
    string? Note,
    string? PayloadJson = null);
