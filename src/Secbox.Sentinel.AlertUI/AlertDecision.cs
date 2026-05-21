namespace Secbox.Sentinel.AlertUI;

// Exit codes the WPF AlertUI returns to the caller (the editor's
// ManagedCallSensor Harmony prefix, which spawned AlertUI synchronously
// and is blocked on WaitForExit). Numeric values are part of the IPC
// contract — DO NOT renumber.
//
// Mirror constants live in Secbox.Core.RuntimeSensors.AlertDecision so
// the prefix and the UI agree without sharing a project reference.
public static class AlertDecision
{
    // Default when the user closes the window without clicking a button
    // — fail safe: block. Library code sees a null Process / false return.
    public const int Block            = 0;
    public const int Allow            = 1;
    public const int AllowAndTrust    = 2;
    public const int Kill             = 3;
    public const int KillAndRemove    = 4; // kill editor + delete the offending library from disk
}
