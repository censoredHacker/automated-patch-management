# Run `patchmgr patch` against the running Windows Docker container (PowerShell).
# Defaults to --dry-run. Pass `-Apply` to actually attempt KB installs.
#
# NOTE: real KB installation inside a Windows Server Core container
# is unreliable — Microsoft does not service running containers via
# Windows Update. The dry-run path exercises the full discover ->
# prioritise -> report flow, which is what this test is for.
[CmdletBinding()]
param(
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if (-not (Get-Command patchmgr -ErrorAction SilentlyContinue)) {
    Write-Error "'patchmgr' is not on PATH. Install it from the repo root first:`n  python -m venv .venv`n  .\.venv\Scripts\Activate.ps1`n  pip install -e ."
    exit 127
}

$Port     = if ($env:PORT)     { $env:PORT }     else { 5986 }
$User     = if ($env:USER)     { $env:USER }     else { 'patchadmin' }
$Pass     = if ($env:PASS)     { $env:PASS }     else { 'patchadmin' }
$Settings = if ($env:SETTINGS) { $env:SETTINGS } else { '.\settings.yaml' }
$Severity = if ($env:SEVERITY) { $env:SEVERITY } else { 'high' }

$dryFlag = if ($Apply) { '--no-dry-run' } else { '--dry-run' }
if ($Apply) { Write-Host "[patch] !!! REAL PATCH RUN (no dry-run) !!!" }

Write-Host "[patch] target=127.0.0.1:$Port user=$User severity-min=$Severity $dryFlag"
patchmgr patch `
    --os windows `
    --target "127.0.0.1:${Port}:${User}:${Pass}" `
    --severity-min $Severity `
    --settings $Settings `
    --report-dir .\reports `
    --reboot manual `
    $dryFlag
