namespace Secbox.Contracts;

public static class BridgeProtocol
{
    // v1 → v2: added AttachRuntimeSensors/DetachRuntimeSensors/GetSensorStatus
    // for the runtime monitoring layer (Tier B profiler + optional Tier A
    // Sentinel). Scan* methods unchanged; adapters built against v1 still
    // get scan results, they just can't enable runtime monitoring.
    public const int CurrentVersion = 2;
    public const int MinSupportedVersion = 1;
    public const string ApiClassName = "Secbox.Core.SecboxApi";

    public const string GetInfoMethodName = "GetInfo";
    public const string ScanFolderMethodName = "ScanFolder";
    public const string ScanAssemblyMethodName = "ScanAssembly";
    public const string ScanSourceMethodName = "ScanSource";

    // Runtime sensors (v2+)
    public const string AttachRuntimeSensorsMethodName = "AttachRuntimeSensors";
    public const string DetachRuntimeSensorsMethodName = "DetachRuntimeSensors";
    public const string GetSensorStatusMethodName = "GetSensorStatus";
}
