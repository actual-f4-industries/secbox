using Secbox.Contracts;

namespace Secbox.Core;

// Returned by SecboxApi.GetInfo(). Lets the editor adapter sanity-check the
// loaded core (version match, available finders/packs) before scanning.
public sealed record ApiInfo(
    int ProtocolVersion,
    string ScannerVersion,
    IReadOnlyList<string> AvailableFinders,
    IReadOnlyList<RulePackInfo> AvailableRulePacks,
    string BuildDate);
