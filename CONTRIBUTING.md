# Contributing to secbox

Thanks for helping make the s&box editor safer to build on. secbox is a static
security scanner plus a runtime enforcement layer for editor libraries; see
[`README.md`](README.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for
the lay of the land.

## Getting started

Requirements: the .NET 10 SDK.

```bash
git clone https://github.com/actual-f4-industries/secbox.git
cd secbox
dotnet build Secbox.slnx -c Release
```

Run the scanner against a folder:

```bash
dotnet run --project src/Secbox.Cli -- info
dotnet run --project src/Secbox.Cli -- scan /path/to/library/folder
```

Output is JSON (`ScanReport`); pipe to `jq` for readability.

## Project layout

| Project | Role |
|---|---|
| `Secbox.Contracts` | DTOs + interfaces, zero deps |
| `Secbox.Rules` | Rule packs + engine-mirror allowlist |
| `Secbox.Scanner` | Finders, pipeline, decision engine |
| `Secbox.Core` | Bridge API (JSON in/out) + Tier E runtime enforcement |
| `Secbox.Cli` | Command line for dev/CI |
| `Secbox.Sentinel.AlertUI` | WPF decision dialog (`SecboxAlertUI.exe`) |

Dependency direction is strictly downhill from `Contracts`. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for detail and
[`docs/BRIDGE_PROTOCOL.md`](docs/BRIDGE_PROTOCOL.md) for the JSON wire format.

## Ways to contribute

### Add a detection rule

Most value lands here. Rules live in `Secbox.Rules` (`CriticalPack`,
`NativeBinaryPack`). Add the pattern to the relevant pack, bump the pack
version, and include a sample library folder that trips it.

### Add a finder

Implement `IFinder` (`Id`, `Description`, `AppliesTo`, `ScanAsync`) and register
it with `FinderRegistry` or pass it to `ScanPipeline`. Keep finders side-effect
free; a throw is caught per-finder but still loses that finder's results.

### Improve runtime enforcement

The Tier E managed-call hook lives in `Secbox.Core/RuntimeSensors`. Patches run
inside the editor process, so every patch body must be wrapped in try/catch: a
throw from a Harmony patch propagates into the patched method and crashes the
editor. Anything that deletes files, intercepts processes, or makes a trust
decision needs a guard and a comment explaining it.

## Coding guidelines

- Target framework is `net10.0`; nullable reference types and implicit usings
  are enabled. Keep both clean (no new warnings).
- Match the style of the surrounding code: comment the *why*, not the *what*.
- No em-dashes in source or docs; use a hyphen.

## Pull requests

1. Branch from `main`.
2. Keep the change focused: one concern per PR.
3. `dotnet build Secbox.slnx -c Release` must succeed with zero warnings. CI
   (`.github/workflows/ci.yml`) builds and runs managed tests on every PR.
4. Use a clear commit subject (a `type: summary` line is appreciated).
5. Update the docs under `docs/` and the `README` when behavior changes.

## Reporting security issues

If you find a way to evade detection, **do not open a public issue**: contact
the maintainer privately first. See
[Reporting security issues](README.md#reporting-security-issues).

## Sponsoring

If secbox saves your machine from a malicious library, consider sponsoring its
development. See [`.github/FUNDING.yml`](.github/FUNDING.yml).
