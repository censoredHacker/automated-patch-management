# Stop and remove the patchmgr-windows-vuln container (PowerShell).
$ErrorActionPreference = 'Stop'
$Name = 'patchmgr-windows-vuln'

$existing = docker ps -a --format '{{.Names}}' | Where-Object { $_ -eq $Name }
if ($existing) {
    Write-Host "[stop] removing $Name"
    docker rm -f $Name | Out-Null
    Write-Host "[stop] done"
} else {
    Write-Host "[stop] $Name is not running"
}
