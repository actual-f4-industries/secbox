# Architecture

## Layout

```
Secbox.Contracts   ← DTOs + interfaces (Finding, Severity, IFinder, IRulePack,
                     IPipeline, BridgeProtocol). No deps. Stable wire format.
Secbox.Rules       ← Rule packs (Critical, NativeBinary) + EngineMirror
                     allowlist + RuleSet regex matcher. Depends on Contracts.
Secbox.Scanner     ← IFinder implementations + ScanPipeline + DecisionEngine.
                     Cecil (IL walker) + Roslyn (source) + System.Reflection.
                     Metadata (metadata tables). Depends on Contracts + Rules.
Secbox.Core        ← Public JSON facade — SecboxApi static class. The single
                     DLL the editor adapter reflects into. Depends on all
                     above.
Secbox.Cli         ← Console wrapper for dev/CI. Depends on Core.
```

Dependency direction is strictly downhill: anything in `Contracts` is referenceable everywhere; nothing references `Cli`. `Core` is the topmost runtime entry point.

## Plugin model

**`IFinder`** is the unit of extensibility. Each detector is a class that:

```csharp
public interface IFinder {
    string Id { get; }
    string Description { get; }
    bool AppliesTo(ScanTarget target);
    Task<IReadOnlyList<Finding>> ScanAsync(ScanTarget, ScanContext, CancellationToken);
}
```

Built-in finders:
- **MetadataFinder** — fast SRM-based metadata-table scan (typerefs, memberrefs, P/Invoke flag, critical attributes, ExplicitLayout).
- **IlFinder** — deep Cecil IL-instruction walker (ldstr suspicious-string detection, ldftn/Finalize trick, pinned locals, per-instruction member refs).
- **SourceFinder** — Roslyn syntax walker for .cs files (suspect using directives, dangerous identifiers, suspicious string literals).
- **NativeBinaryFinder** — PE-header inspection of .dll files, extension check for .so/.dylib/.exe/.bat/.ps1/.sh.

New finders drop in by implementing `IFinder` and registering with `FinderRegistry` or passing directly to `ScanPipeline` constructor.

## Rule packs

**`IRulePack`** = versioned, attributable bundle of rules. Each `Rule` has `Id`, `Severity`, `Pattern`, optional `Rationale`/`FixHint`/`Category`.

Packs are denylists (matched-pattern → finding). The engine-mirror is treated separately as an allowlist (unmatched-pattern → finding) because of inverted semantics — it lives at `Secbox.Rules.EngineMirror`, not in a pack.

Built-in packs:
- **CriticalPack** — always-flag patterns: interop, process, dynamic code, raw network, filesystem, dangerous reflection, environment.
- **NativeBinaryPack** — metadata-only pack documenting the rules NativeBinaryFinder enforces.

Add a custom pack by implementing `IRulePack` and registering with `PackRegistry` or passing to `ScanPipeline`.

## Pipeline

`ScanPipeline.ScanAsync(target, options, policy)` does:

1. Filter finders by `options.FindersToRun` (if specified).
2. Filter packs by `options.RulePacksToRun` (if specified).
3. Build `ScanContext` (options, policy, packs).
4. For each applicable finder, dispatch + collect findings (errors caught per-finder).
5. Filter by `options.MinSeverity`.
6. Dedupe by `(RuleId, Location)`.
7. Cap at `options.MaxFindings`.
8. `DecisionEngine.DecideOverall(findings, policy)` → overall `Decision`.
9. Return immutable `ScanReport` (JSON-serializable, includes timestamps + pack versions + protocol version + scanner version).

## Decision engine

`IDecisionEngine` translates findings → actions according to `Policy`:

- Per-finding: blocklist > allowlist > critical-and-block-by-default > prompt-threshold > allow-once.
- Overall: worst per-finding decision wins (ranked Block > Quarantine > Unreviewed > AllowOnce > TrustAlways).

`DefaultDecisionEngine` is the built-in implementation. Replace via the `ScanPipeline` constructor.

## Bridge

`Secbox.Core.SecboxApi` is the ONLY surface area the editor adapter touches via reflection. JSON in/out — the adapter never references `Secbox.Contracts` types at compile time (editor regenerates the adapter's csproj and would strip custom references).

See [`BRIDGE_PROTOCOL.md`](BRIDGE_PROTOCOL.md) for the wire format.

## Versioning

- **ProtocolVersion** (`BridgeProtocol.CurrentVersion`) — bumped when the bridge API method signatures or JSON schema change incompatibly.
- **ScannerVersion** — assembly version of `Secbox.Core.dll`.
- **RulePack version** — each pack has its own semver; bumped on rule additions/changes.

ScanReport includes all three so consumers can diff/audit over time.
