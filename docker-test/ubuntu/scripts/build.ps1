# Build the patchmgr/ubuntu-vuln:focal image (PowerShell).
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

Write-Host "[build] docker build -> patchmgr/ubuntu-vuln:focal"
docker build -t patchmgr/ubuntu-vuln:focal -f Dockerfile .
Write-Host "[build] done. Run scripts/run.ps1 next."
