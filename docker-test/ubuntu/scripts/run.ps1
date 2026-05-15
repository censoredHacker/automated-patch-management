# Start (or restart) the patchmgr-ubuntu-vuln container (PowerShell).
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

$Name = 'patchmgr-ubuntu-vuln'
$Port = if ($env:PORT) { $env:PORT } else { 2222 }

$existing = docker ps -a --format '{{.Names}}' | Where-Object { $_ -eq $Name }
if ($existing) {
    Write-Host "[run] removing existing container $Name"
    docker rm -f $Name | Out-Null
}

Write-Host "[run] starting $Name on 127.0.0.1:$Port"
docker run -d `
    --name $Name `
    --hostname ubuntu-vuln `
    -p "127.0.0.1:${Port}:22" `
    patchmgr/ubuntu-vuln:focal | Out-Null

for ($i = 1; $i -le 15; $i++) {
    $up = docker exec $Name pgrep -x sshd 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[run] sshd is up"
        break
    }
    Start-Sleep -Seconds 1
}

Write-Host "[run] connect with:  ssh -p $Port patchadmin@127.0.0.1   (password: patchadmin)"
Write-Host "[run] stop with:     scripts\stop.ps1"
