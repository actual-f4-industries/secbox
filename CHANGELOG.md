# Changelog

All notable changes to **secbox** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-21

First public release - a security scanner and runtime enforcement layer for
s&box editor libraries, distributed as a downloadable bridge bundle the
`secbox.editor` adapter fetches, SHA-256-verifies, and loads into the editor.

### Added

**Static scanner** (`Secbox.Core` · `Secbox.Scanner` · `Secbox.Rules` · `Secbox.Contracts`)

- `SecboxApi` bridge surface (JSON in/out) for folder / assembly / source scans -
  the single type the adapter reflects into.
- Four finders: **Metadata** (SRM metadata tables, P/Invoke flag, critical
  attributes), **IL** (Cecil instruction walk), **Source** (Roslyn syntax walk),
  **NativeBinary** (PE-header + extension inspection).
- Rule packs: **CriticalPack** (interop, process spawn, dynamic code, raw network,
  filesystem, dangerous reflection, environment) and **NativeBinaryPack**, plus the
  engine-mirror allowlist.
- `ScanPipeline` + `DecisionEngine` producing an immutable, JSON-serializable
  `ScanReport` (findings, pack versions, protocol + scanner version).
- `Secbox.Cli` - standalone command line for dev/CI scanning.

**Runtime enforcement - Tier E** (`Secbox.Core/RuntimeSensors`)

- In-editor managed-call tripwire: a Harmony runtime patch on
  `System.Diagnostics.Process.Start` (static + instance overloads).
- Library attribution by stack walk (isolated `AssemblyLoadContext`, `package.`
  assembly prefix, or `\Libraries\` / `\.bin\` path); editor, engine, and secbox
  frames are never flagged.
- Intercepted library-attributed spawns **suspend the calling thread** until the
  user decides. Per-library trust persists to
  `%LOCALAPPDATA%\secbox\managed-call-trust.json`.

**Decision dialog** (`Secbox.Sentinel.AlertUI`)

- Self-contained single-file WPF dialog (`SecboxAlertUI.exe`) shown while a
  library call is suspended. Decisions: **Allow once**, **Allow & Trust library**,
  **Kill editor**, **Kill & remove library**.
- **Kill & remove library** terminates the editor and deletes the offending
  library folder from the project's `Libraries\`; any files still locked are
  removed on the next editor start. The delete is path-guarded to a direct child
  of a `Libraries\` folder.
- secbox branding: borderless window with custom title bar (logo + wordmark),
  drop shadow, and dark theme (background `#080d14` / foreground `#efefef` /
  accent `#07cd8d`).

**Distribution**

- GitHub Actions **CI** (Release build + managed tests) and **Release** (builds
  the bridge bundle, computes SHA-256s, optional SignPath signing, publishes a
  GitHub Release with `hashes.txt`).
- Bundle: `Secbox.Core.dll` + dependencies (`Secbox.Contracts`, `Secbox.Rules`,
  `Secbox.Scanner`, `Mono.Cecil`, `0Harmony`) + `SecboxAlertUI.exe`.

### Security

- Every downloaded bridge file is SHA-256-pinned in the adapter's
  `CorePolicy.CoreFiles`; any mismatch is refused.
- See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for what these layers do and
  do not defend against.

### Notes

- The native CLR profiler (Tier B) and the Sentinel ETW service + MSI (Tier A)
  were prototyped during development but **removed before this release**. 0.1.0 is
  enforcement-only (Tier E). They never shipped, so there is nothing to migrate.

[0.1.0]: https://github.com/actual-f4-industries/secbox/releases/tag/0.1.0-release
