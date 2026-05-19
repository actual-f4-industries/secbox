namespace Secbox.Core.RuntimeSensors;

// Normalized event surfaced by any sensor. Crosses the correlator and the
// output sinks. JSON-serializable for log shipping.
public sealed record SensorEvent(
    long Sequence,
    string SensorId,              // ISensor.Id that produced it
    SensorEventKind Kind,
    DateTimeOffset Timestamp,
    int Pid,
    int Tid,
    string? Target,               // path, image, endpoint, registry key — kind-dependent
    string? PayloadJson = null);

public enum SensorEventKind
{
    Unknown = 0,

    // Tier B / managed
    AssemblyLoaded = 1000,
    ModuleLoaded = 1001,
    MethodJitted = 1002,
    DynamicMethodEmitted = 1003,
    ExceptionThrown = 1004,
    ProfilerAttached = 1099,

    // Tier E / managed-call tripwires (Harmony-patched APIs intercepted in
    // the editor process). Used to mark "library code attempted X" with
    // attribution before the resulting kernel event reaches the correlator.
    ManagedProcessStart = 1200,
    ManagedFileWrite = 1201,
    ManagedHttpRequest = 1202,
    ManagedAssemblyLoadFrom = 1203,

    // Tier A / kernel (mirror of Sentinel.Contracts.KernelEventKind)
    FileCreate = 2100,
    FileWrite = 2101,
    FileDelete = 2102,
    FileRename = 2103,
    FileSetSecurity = 2104,
    ProcessStart = 2200,
    ProcessStop = 2201,
    NativeImageLoad = 2202,
    NetTcpConnect = 2300,
    NetTcpSend = 2301,
    NetTcpRecv = 2302,
    NetUdpSend = 2310,
    NetUdpRecv = 2311,
    RegOpenKey = 2400,
    RegSetValue = 2401,
    RegDeleteKey = 2402,
    RegDeleteValue = 2403,
}
