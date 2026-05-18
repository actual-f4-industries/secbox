# Secbox

Security scanner for s&box editor libraries. Detects dangerous APIs (filesystem, P/Invoke, process spawning, dynamic code loading) inside Library-Manager-installed editor extensions before they damage your machine.

Distributed as a downloadable backend that the `secbox` s&box library (the
"adapter") fetches, verifies, and bridges into the editor.

## Projects

| Project | Role |
|---|---|
| `Secbox.Contracts` | DTOs + interfaces, zero deps |
| `Secbox.Rules` | Rule packs + engine-mirror allowlist + regex matcher |
| `Secbox.Scanner` | Finders (Metadata/IL/Source/NativeBinary), pipeline, decision engine |
| `Secbox.Core` | Public bridge API — JSON in/out, the DLL the adapter loads |
| `Secbox.Cli` | Standalone command-line for dev/CI use |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for design rationale,
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for what we defend against and
what we cannot, [`docs/BRIDGE_PROTOCOL.md`](docs/BRIDGE_PROTOCOL.md) for the
JSON wire format between adapter and core.

## Quickstart

```bash
dotnet build
dotnet run --project src/Secbox.Cli -- info
dotnet run --project src/Secbox.Cli -- scan /path/to/library/folder
```

Output is JSON (`ScanReport` schema). Pipe to `jq` for readability.

## Distribution

Bridge artifacts (`Secbox.Core.dll`, dependencies, native CLR profiler, and
the Sentinel MSI) are published as GitHub Release assets at
[`actual-f4-industries/secbox/releases`](https://github.com/actual-f4-industries/secbox/releases).
The s&box adapter resolves them via

```
https://github.com/actual-f4-industries/secbox/releases/download/<tag>/<file>
```

and refuses any blob whose SHA-256 doesn't match the value pinned in the
adapter's `CorePolicy.CoreFiles`. Each release also attaches a `hashes.txt`
manifest so adapter maintainers can sync the pins in one step.

## Reporting security issues

If you find a way to evade detection, please contact the maintainer privately
before opening a public issue.
