# Build the patchmgr/windows-vuln:ltsc2022 image (PowerShell).
#
# Requires Docker Desktop in Windows-containers mode.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

Write-Host "[build] docker build -> patchmgr/windows-vuln:ltsc2022"
docker build -t patchmgr/windows-vuln:ltsc2022 -f Dockerfile .
if ($LASTEXITCODE -ne 0) { throw "docker build failed (exit=$LASTEXITCODE)" }
Write-Host "[build] done. Run scripts\run.ps1 next."
