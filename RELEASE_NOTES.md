Bridge bundle for the s&box editor security library - `Secbox.Core` + its
dependencies + the `SecboxAlertUI` decision dialog.

The s&box adapter (`secbox.editor`) downloads these assets at runtime from
`https://github.com/actual-f4-industries/secbox/releases/download/<tag>/<file>`,
verifies each blob's SHA-256 against the value pinned in `CorePolicy.CoreFiles`,
then loads `Secbox.Core.dll` into an isolated `AssemblyLoadContext`.

## Updating the adapter to this release

1. Download `hashes.txt` (attached below).
2. Paste each `<sha>  <filename>` pair into `CorePolicy.CoreFiles` in the adapter,
   replacing the `00000…` placeholders.
3. Bump `CorePolicy.CoreVersion` to match this release's tag.
4. Re-publish `secbox.editor` to the s&box Library Manager.

## What's in the bundle

| File | Purpose |
|---|---|
| `Secbox.Core.dll` | Public bridge surface + runtime enforcement (Tier E) - the DLL the adapter reflects into |
| `Secbox.Contracts.dll` | DTOs + interfaces (`Finding`, `Severity`, `BridgeProtocol`, …) |
| `Secbox.Rules.dll` | Rule packs (`CriticalPack`, `NativeBinaryPack`) + engine-mirror allowlist |
| `Secbox.Scanner.dll` | Finders + pipeline + decision engine |
| `Mono.Cecil.dll` | IL walker used by `IlFinder` |
| `0Harmony.dll` | Runtime IL patching for the Tier E managed-call hook |
| `SecboxAlertUI.exe` | Self-contained WPF decision dialog shown for a suspended library call |
| `hashes.txt` | SHA-256 of every artifact above |

## Detection & enforcement

- **Static scan** - folder / assembly / source scanning surfaces dangerous APIs
  (filesystem, process spawn, P/Invoke, dynamic code, raw network) before a
  library is trusted.
- **Runtime enforcement (Tier E)** - a Harmony hook intercepts library-attributed
  `System.Diagnostics.Process.Start` in the editor, suspends the calling thread,
  and prompts via `SecboxAlertUI`: Allow once / Allow & Trust / Kill editor /
  Kill & remove library.

> The earlier detection tiers - the native CLR profiler (Tier B) and the Sentinel
> ETW service + MSI (Tier A) - were removed before 0.1.0. This release is
> enforcement-only.

See [`docs/THREAT_MODEL.md`](https://github.com/actual-f4-industries/secbox/blob/main/docs/THREAT_MODEL.md)
for what these layers do and do not defend against, and
[`docs/ARCHITECTURE.md`](https://github.com/actual-f4-industries/secbox/blob/main/docs/ARCHITECTURE.md)
for how they compose.
