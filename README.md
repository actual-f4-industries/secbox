# Secbox

Security scanner **and runtime enforcement layer** for s&box editor libraries.
Detects dangerous APIs (filesystem, P/Invoke, process spawning, dynamic code
loading) inside Library-Manager-installed editor extensions before they damage
your machine - and, at runtime, intercepts library-attributed process spawns in
the editor and prompts you for a decision.

Distributed as a downloadable backend that the `secbox` s&box library (the
"adapter") fetches, verifies, and bridges into the editor.

## Projects

| Project | Role |
|---|---|
| `Secbox.Contracts` | DTOs + interfaces, zero deps |
| `Secbox.Rules` | Rule packs + engine-mirror allowlist + regex matcher |
| `Secbox.Scanner` | Finders (Metadata/IL/Source/NativeBinary), pipeline, decision engine |
| `Secbox.Core` | Public bridge API (JSON in/out) **+ runtime enforcement (Tier E managed-call hook)** - the DLL the adapter loads |
| `Secbox.Cli` | Standalone command-line for dev/CI use |
| `Secbox.Sentinel.AlertUI` | Self-contained WPF decision dialog (`SecboxAlertUI.exe`) shown when a suspended library call needs a verdict |

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

## Runtime enforcement (Tier E)

Static scanning is advisory - it runs before you trust a library. Inside the
editor, secbox also installs a runtime tripwire (`Secbox.Core/RuntimeSensors`):
a Harmony patch on `System.Diagnostics.Process.Start`. When a call is attributed
to a library (by load context, the `package.` assembly prefix, or a `\Libraries\`
/ `\.bin\` path), the calling thread is **suspended** and `SecboxAlertUI.exe`
asks you to decide:

- **Allow once** - let this call through; prompt again next time.
- **Allow & Trust library** - let through and stop prompting for this library
  (persisted to `%LOCALAPPDATA%\secbox\managed-call-trust.json`).
- **Kill editor** - terminate the editor immediately.
- **Kill & remove library** - terminate the editor *and* delete the offending
  library from the project's `Libraries\` folder (files still locked are removed
  on the next editor start).

Editor, engine, and secbox's own calls are never intercepted. The native CLR
profiler (Tier B) and Sentinel ETW service (Tier A) were removed before 0.1.0;
this release is enforcement-only.

## Distribution

Bridge artifacts (`Secbox.Core.dll`, its dependencies, and the
`SecboxAlertUI.exe` decision dialog) are published as GitHub Release assets at
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
