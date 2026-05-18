# Pulls the CoreCLR profiler API headers from dotnet/runtime into
# externals/coreclr-pal-headers/. Run once after cloning the repo. The
# CMake build refuses to configure without these headers.
#
# Each file has a fallback path list — dotnet/runtime occasionally moves
# headers between branches, so we try a couple of known locations before
# giving up. Required headers fail the script; optional ones just warn.
#
# On Windows, sal.h is intentionally NOT vendored — the Windows SDK
# provides it and the CoreCLR headers pick it up transitively via the
# standard include path.

[CmdletBinding()]
param(
    [string] $RuntimeRef = "v9.0.0",
    [string] $OutDir = (Join-Path $PSScriptRoot ".." "externals" "coreclr-pal-headers"),
    [switch] $Verbose
)

# Don't $ErrorActionPreference=Stop — we handle 404s per file.
$ErrorActionPreference = "Continue"

$rawBase = "https://raw.githubusercontent.com/dotnet/runtime/$RuntimeRef"

# Each entry: { LeafName, Required, CandidatePaths... }. The script
# downloads to $OutDir/<LeafName> on the first successful path.
$headers = @(
    @{ Name = "corprof.h"; Required = $true;  Paths = @(
        "src/coreclr/pal/prebuilt/inc/corprof.h",
        "src/coreclr/inc/corprof.h"
    )},
    @{ Name = "cor.h";     Required = $true;  Paths = @(
        "src/coreclr/inc/cor.h"
    )},
    @{ Name = "corhdr.h";  Required = $true;  Paths = @(
        "src/coreclr/inc/corhdr.h"
    )},
    @{ Name = "corerror.h"; Required = $false; Paths = @(
        "src/coreclr/inc/corerror.h",
        "src/coreclr/pal/prebuilt/inc/corerror.h"
    )}
    # sal.h intentionally omitted on Windows (SDK provides it). The
    # POSIX build (Linux/macOS) would need this; add when expanding
    # beyond win-x64.
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$failed = @()
foreach ($h in $headers) {
    $dest = Join-Path $OutDir $h.Name
    $got = $false
    foreach ($p in $h.Paths) {
        $url = "$rawBase/$p"
        Write-Host "trying $($h.Name) <- $url"
        try {
            Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -ErrorAction Stop
            Write-Host "  ok ($((Get-Item $dest).Length) bytes)"
            $got = $true
            break
        }
        catch {
            $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            Write-Host "  miss ($code)"
        }
    }
    if (-not $got) {
        if ($h.Required) {
            $failed += $h.Name
            Write-Error "REQUIRED header $($h.Name) could not be fetched from any candidate path."
        } else {
            Write-Warning "Optional header $($h.Name) skipped — build will continue."
        }
    }
}

if ($failed.Count -gt 0) {
    Write-Error "Failed to fetch: $($failed -join ', '). Bump `$RuntimeRef` (current: $RuntimeRef) or vendor the headers manually under $OutDir."
    exit 1
}

Write-Host "Done. Headers in $OutDir"
