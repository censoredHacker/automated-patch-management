# Stop and remove the patchmgr-ubuntu-vuln container (PowerShell).
$ErrorActionPreference = 'Stop'
$Name = 'patchmgr-ubuntu-vuln'

$existing = docker ps -a --format '{{.Names}}' | Where-Object { $_ -eq $Name }
if ($existing) {
    Write-Host "[stop] removing $Name"
    docker rm -f $Name | Out-Null
    Write-Host "[stop] done"
} else {
    Write-Host "[stop] $Name is not running"
}
