Bridge bundle (`Secbox.Core` + dependencies), native CLR profiler (Tier B), and
Sentinel installer (Tier A) for the s&box editor security library.

The s&box adapter (`secbox.editor`) downloads these assets at runtime from
`https://github.com/actual-f4-industries/secbox/releases/download/<tag>/<file>`,
verifies each blob's SHA-256 against the value pinned in `CorePolicy.CoreFiles`,
then loads `Secbox.Core.dll` into an isolated `AssemblyLoadContext`.

## Updating the adapter to this release

1. Download `hashes.txt` (attached below).
2. Paste each `<sha>  <filename>` pair into `CorePolicy.CoreFiles` in the adapter,
   replacing the `00000…` placeholders.
3. Paste the `secbox-profiler-win-x64.dll` hash into `ProfilerHashes.ExpectedSha256WinX64`
   in `src/Secbox.Core/Profiler/ProfilerHashes.cs`.
4. Bump `CorePolicy.CoreVersion` to match this release's tag.
5. Re-publish `secbox.editor` to the s&box Library Manager.

## What's in the bundle

| File | Purpose |
|---|---|
| `Secbox.Core.dll` | Public bridge surface — the DLL the adapter reflects into |
| `Secbox.Contracts.dll` | DTOs + interfaces (`Finding`, `Severity`, `BridgeProtocol`, …) |
| `Secbox.Rules.dll` | Rule packs (`CriticalPack`, `NativeBinaryPack`) + engine-mirror allowlist |
| `Secbox.Scanner.dll` | Finders + pipeline + decision engine |
| `Secbox.Sentinel.Contracts.dll` | Wire DTOs for the kernel-monitoring sidecar |
| `Secbox.Sentinel.Client.dll` | In-process client for the Sentinel service |
| `Microsoft.Diagnostics.NETCore.Client.dll` | Used by `ProfilerCoordinator.AttachProfiler` |
| `Mono.Cecil.dll` | IL walker used by `IlFinder` |
| `secbox-profiler-win-x64.dll` | Tier B — native CLR profiler (attached in-process) |
| `SecboxSentinel.msi` | Tier A — optional admin-installed Windows Service |
| `hashes.txt` | SHA-256 of every artifact above |

See [`docs/THREAT_MODEL.md`](https://github.com/actual-f4-industries/secbox/blob/main/docs/THREAT_MODEL.md)
for what these layers do and do not defend against, and
[`docs/ARCHITECTURE.md`](https://github.com/actual-f4-industries/secbox/blob/main/docs/ARCHITECTURE.md)
for how they compose.
