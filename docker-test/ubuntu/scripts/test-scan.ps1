# Run `patchmgr scan` against the running Docker container (PowerShell).
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if (-not (Get-Command patchmgr -ErrorAction SilentlyContinue)) {
    Write-Error "'patchmgr' is not on PATH. Install it from the repo root first:`n  python -m venv .venv`n  .\.venv\Scripts\Activate.ps1`n  pip install -e ."
    exit 127
}

$Port     = if ($env:PORT)     { $env:PORT }     else { 2222 }
$Settings = if ($env:SETTINGS) { $env:SETTINGS } else { '.\settings.yaml' }
$Severity = if ($env:SEVERITY) { $env:SEVERITY } else { 'medium' }

Write-Host "[scan] target=127.0.0.1:$Port  severity-min=$Severity"
patchmgr scan `
    --os linux `
    --target "127.0.0.1:${Port}:patchadmin:patchadmin" `
    --severity-min $Severity `
    --settings $Settings `
    --report-dir .\reports
