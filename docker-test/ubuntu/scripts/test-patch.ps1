# Run `patchmgr patch` against the running Docker container (PowerShell).
# Defaults to --dry-run. Pass `-Apply` to actually install.
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

$Port     = if ($env:PORT)     { $env:PORT }     else { 2222 }
$Settings = if ($env:SETTINGS) { $env:SETTINGS } else { '.\settings.yaml' }
$Severity = if ($env:SEVERITY) { $env:SEVERITY } else { 'high' }

$dryFlag = if ($Apply) { '--no-dry-run' } else { '--dry-run' }
if ($Apply) { Write-Host "[patch] !!! REAL PATCH RUN (no dry-run) !!!" }

Write-Host "[patch] target=127.0.0.1:$Port  severity-min=$Severity  $dryFlag"
patchmgr patch `
    --os linux `
    --target "127.0.0.1:${Port}:patchadmin:patchadmin" `
    --severity-min $Severity `
    --settings $Settings `
    --report-dir .\reports `
    --reboot manual `
    $dryFlag
