# Bridge Protocol

JSON wire format between the s&box-side editor adapter (`secbox.editor.dll`)
and the downloaded scanner backend (`Secbox.Core.dll`).

The editor adapter:
1. Downloads `Secbox.Core.dll` (and its dependency DLLs) from a CDN.
2. Verifies the SHA-256 hash against a value pinned in the adapter source.
3. Loads into a dedicated `AssemblyLoadContext`.
4. Reflectively invokes `Secbox.Core.SecboxApi` methods (names pinned in `BridgeProtocol`).
5. Deserializes returned JSON into local mirror DTOs.

## API surface

```csharp
namespace Secbox.Core;

public static class SecboxApi
{
    public static string GetInfo();
    public static string ScanFolder(string folderPath, string? optionsJson);
    public static string ScanAssembly(string dllPath, string? optionsJson);
    public static string ScanSource(string sourcePath, string? optionsJson);
}
```

All methods are synchronous, string in/out. The adapter wraps in Tasks if
async behavior is needed at the caller.

## Version negotiation

```csharp
public static class BridgeProtocol
{
    public const int CurrentVersion = 1;
    public const int MinSupportedVersion = 1;
}
```

On load, adapter calls `GetInfo()` → parses `protocolVersion` field. If
`info.protocolVersion < adapter.MinSupportedVersion` or
`info.protocolVersion > adapter.CurrentVersion`, adapter refuses to bridge
and reports an upgrade/downgrade requirement.

## Wire schema

### GetInfo() response

```json
{
  "protocolVersion": 1,
  "scannerVersion": "1.0.0.0",
  "availableFinders": ["metadata", "il", "source", "native-binary"],
  "availableRulePacks": [
    {
      "id": "critical.v1",
      "version": "1.0.0",
      "source": "Secbox.Rules.Packs.CriticalPack",
      "description": "Always-flag attack patterns. ...",
      "ruleCount": 74
    }
  ],
  "buildDate": "2026-05-18T00:00:00.000Z"
}
```

### Scan request (optionsJson)

```json
{
  "options": {
    "minSeverity": "Low",
    "maxFindings": 1000,
    "findersToRun": null,
    "rulePacksToRun": null,
    "includeIlWalk": true,
    "includeSourceScan": true
  },
  "policy": {
    "promptThreshold": "Medium",
    "blockCriticalByDefault": true,
    "blockUnmanagedDlls": true,
    "ruleAllowlist": null,
    "ruleBlocklist": null
  }
}
```

Pass `null` or empty string for default options + policy.

### Scan response (ScanReport)

```json
{
  "target": "C:/path/to/library/folder",
  "startedAt": "2026-05-18T00:00:00.000Z",
  "completedAt": "2026-05-18T00:00:01.000Z",
  "findings": [
    {
      "severity": "Critical",
      "ruleId": "critical.filesystem.001",
      "message": "Hits critical.v1: System.Private.CoreLib/System.IO.File.Delete",
      "location": "Editor/SCFU.cs :: SCFU::Cleanup",
      "evidence": null,
      "fixHint": null,
      "finderId": "il"
    }
  ],
  "rulePacksUsed": [ /* RulePackInfo[] */ ],
  "scannerVersion": "1.0.0.0",
  "protocolVersion": 1,
  "overall": "Block"
}
```

### Severity enum

`"Info" | "Low" | "Medium" | "High" | "Critical"` - JSON string (configured via `JsonStringEnumConverter`).

### Decision enum

`"Unreviewed" | "AllowOnce" | "TrustAlways" | "Block" | "Quarantine"`

## Forward-compatibility

- Adding new optional fields to request/response = same protocol version.
- Adding new finders/packs = same protocol version (just appear in `availableFinders`/`availableRulePacks`).
- Renaming methods, changing existing field semantics, removing fields = **bump `CurrentVersion`**.

The adapter must tolerate unknown fields in responses (forward-compat).
