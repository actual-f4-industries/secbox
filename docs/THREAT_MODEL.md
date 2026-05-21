# Threat Model

## What Secbox defends against

The s&box editor loads any library you install from the Library Manager into
the editor process. Editor code is **explicitly unsandboxed** per Facepunch's
own docs (`editor/editor-project.md:13-15`):

> Editor projects are not sandboxed. They are not limited by any whitelists
> and can run any functions. You should be careful when running code you have
> received from an untrusted source - because it can do almost anything.

Concrete attack surface a malicious editor library can exploit:

| Attack | Detection layer |
|---|---|
| `System.IO.File.Delete` your work | CriticalPack.Filesystem (Metadata + IL + Source finders) |
| `System.Diagnostics.Process.Start` arbitrary commands | CriticalPack.Process |
| `[DllImport("kernel32")]` P/Invoke to native code | MetadataFinder PInvokeImpl flag + CriticalPack.Interop |
| Dynamic `Assembly.LoadFile` of a downloaded payload | CriticalPack.DynamicCode |
| Raw `System.Net.Sockets` exfiltration | CriticalPack.RawNetwork |
| Registry tampering via `Microsoft.Win32.Registry` | CriticalPack.Environment |
| Shipped `.exe`/`.so`/native `.dll` | NativeBinaryFinder |
| `kernel32`/`powershell`/`VirtualAlloc` literal in IL or source | SuspiciousLiteral detection (IL ldstr + Source string literal) |

### Runtime interception (Tier E)

Beyond static detection, secbox installs a runtime tripwire on
`System.Diagnostics.Process.Start` inside the editor. A library-attributed
process spawn **suspends the calling thread** and prompts for a decision - allow
once, trust, kill the editor, or kill & remove the library. This catches spawns
that static analysis missed (including those reached via obfuscation or
dynamically generated code) at the moment they execute, and lets you delete the
offending library on the spot.

It deliberately targets process spawning - the highest-signal sink - not every
dangerous API; an in-process attacker can still reach other sinks directly (see
limitation 2 below).

## What Secbox cannot defend against

1. **Load-order race.** If a malicious package loaded *before* secbox in this
   project, its static constructors already ran. We detect on next boot and
   offer uninstall, but cannot undo the first execution. Install secbox
   first in any new project.

2. **Same-process attack surface.** The secbox editor adapter and the
   downloaded `Secbox.Core` both run in-process with full editor privileges.
   A package loaded before secbox could in theory `File.Delete` the trust
   store, hook our dialog via reflection, or shim our type lookups. True
   isolation needs Facepunch engine-side support.

3. **Static analysis bypasses.** Sophisticated adversaries can defeat naive
   pattern matching with:
   - Obfuscation (rename + indirect references)
   - Dynamic codegen (`CSharpScript`, `Reflection.Emit`)
   - Stage-1 payload fetched at runtime via `HttpClient` + `Assembly.Load`
   - Calling engine APIs that themselves wrap unsafe operations

   Secbox catches the lazy 95% directly. Mitigations:
   - Any use of dynamic code loading → Critical regardless of payload
   - Any P/Invoke → Critical (flag-based, not attribute-based, so renames don't help)
   - Any native binary in package → Critical

4. **Trust footprint of the bridge.** The editor adapter downloads
   `Secbox.Core.dll` from a CDN and loads it in-process. Mitigations:
   - SHA-256 hash pinned in adapter source - refuses to load mismatch
   - HTTPS-only host
   - Reproducible build of Secbox.Core (publicly auditable)

   Users still must trust the maintainer's CDN + signing key. This is
   acknowledged in the README.

5. **False sense of security.** A "passes secbox" verdict is not a proof of
   safety - it means "no pattern matched our current rule set". New attack
   vectors require new rules.

## Trust boundaries

```
┌────────────────────────────────────────────────────────────┐
│ s&box editor process (full host privileges)                │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ User code    │    │ Third-party  │    │ secbox.editor│  │
│  │ (your game)  │    │ library      │    │ (adapter)    │  │
│  └──────────────┘    └──────────────┘    └──────┬───────┘  │
│                                                  │ loads   │
│                                          ┌───────▼──────┐  │
│                                          │ Secbox.Core  │  │
│                                          │ (scanner)    │  │
│                                          └──────────────┘  │
└────────────────────────────────────────────────────────────┘
```

Every box in this diagram has the same OS privileges. The boundary secbox
enforces is **policy**, not isolation: it can detect a malicious neighbor
but cannot prevent that neighbor from misbehaving once running.

## Reporting

If you find a detection evasion, contact the maintainer privately rather
than opening a public issue.
