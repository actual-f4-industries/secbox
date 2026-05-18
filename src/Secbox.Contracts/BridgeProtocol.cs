namespace Secbox.Contracts;

public static class BridgeProtocol
{
    public const int CurrentVersion = 1;
    public const int MinSupportedVersion = 1;
    public const string ApiClassName = "Secbox.Core.SecboxApi";
    public const string GetInfoMethodName = "GetInfo";
    public const string ScanFolderMethodName = "ScanFolder";
    public const string ScanAssemblyMethodName = "ScanAssembly";
    public const string ScanSourceMethodName = "ScanSource";
}
