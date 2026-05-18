namespace Secbox.Sentinel.Contracts;

// Normalized event kinds we surface from the kernel. Maps roughly to the
// ETW providers we subscribe to. Designed to be stable across OS providers
// so a future eBPF backend can emit the same values without breaking the
// wire contract.
public enum KernelEventKind
{
    Unknown = 0,

    // --- File (Microsoft-Windows-Kernel-File) ---
    FileCreate = 100,       // open or create (any mode)
    FileWrite = 101,
    FileDelete = 102,
    FileRename = 103,
    FileSetSecurity = 104,

    // --- Process (Microsoft-Windows-Kernel-Process) ---
    ProcessStart = 200,
    ProcessStop = 201,
    ImageLoad = 202,        // module loaded into the process

    // --- Network (Microsoft-Windows-Kernel-Network) ---
    NetTcpConnect = 300,
    NetTcpSend = 301,
    NetTcpRecv = 302,
    NetUdpSend = 310,
    NetUdpRecv = 311,
    NetDnsQuery = 320,

    // --- Registry (Microsoft-Windows-Kernel-Registry) ---
    RegOpenKey = 400,
    RegSetValue = 401,
    RegDeleteKey = 402,
    RegDeleteValue = 403,
}
