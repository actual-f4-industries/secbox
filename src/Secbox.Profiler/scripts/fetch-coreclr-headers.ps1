# Pulls the CoreCLR profiler API headers from dotnet/runtime into
# externals/coreclr-pal-headers/. Run once after cloning the repo. The
# CMake build refuses to configure without these headers.
#
# We pin to a specific runtime commit so header semantics don't shift
# silently when dotnet/runtime moves; bump RuntimeRef when consciously
# upgrading.

[CmdletBinding()]
param(
    [string] $RuntimeRef = "v9.0.0",
    [string] $OutDir = (Join-Path $PSScriptRoot ".." "externals" "coreclr-pal-headers")
)

$ErrorActionPreference = "Stop"

$rawBase = "https://raw.githubusercontent.com/dotnet/runtime/$RuntimeRef/src/coreclr"
$files = @(
    "pal/prebuilt/inc/corprof.h",
    "inc/cor.h",
    "inc/corhdr.h",
    "inc/corerror.h",
    "pal/inc/rt/sal.h"
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
foreach ($f in $files) {
    $dest = Join-Path $OutDir (Split-Path -Leaf $f)
    Write-Host "fetching $f"
    Invoke-WebRequest -Uri "$rawBase/$f" -OutFile $dest
}
Write-Host "Done. Headers in $OutDir"
