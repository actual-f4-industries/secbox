using Secbox.Contracts;

namespace Secbox.Rules;

// Mirror of s&box engine's Sandbox.Access AccessControl. Treats the engine's
// game-side whitelist as ground truth: any member referenced by editor code
// that is NOT on this whitelist becomes a Medium finding (because the same
// code would be rejected if it ran in the game sandbox).
//
// Distinct from IRulePack — packs are denylists (matched-pattern → finding);
// this is an allowlist (unmatched-pattern → finding). Exposed as a RuleSet so
// finders can query IsAllowed / IsAssemblyAllowed directly.
public static class EngineMirror
{
    public const string Version = "1.0.0";
    public const string Source = "sbox-public/engine/Sandbox.Access (snapshot 2026-05-18)";

    public static RuleSet Build()
    {
        var rs = new RuleSet();
        foreach (var a in EngineMirrorData.Assemblies) rs.AddAssembly(a);
        rs.AddRules(EngineMirrorData.BaseAccess);
        rs.AddRules(EngineMirrorData.Types);
        rs.AddRules(EngineMirrorData.Reflection);
        rs.AddRules(EngineMirrorData.Async);
        rs.AddRules(EngineMirrorData.Exceptions);
        rs.AddRules(EngineMirrorData.Diagnostics);
        rs.AddRules(EngineMirrorData.CompilerGenerated);
        return rs;
    }

    public static RulePackInfo AsInfo() => new(
        Id: "engine.mirror",
        Version: Version,
        Source: Source,
        Description: "Engine AccessControl whitelist (allowlist mode). Findings produced when editor code references members the engine wouldn't permit in game code.",
        RuleCount: EngineMirrorData.TotalRuleCount);
}
