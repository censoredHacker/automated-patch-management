# Start (or restart) the patchmgr-windows-vuln container (PowerShell).
#
# Publishes WinRM/HTTPS on 127.0.0.1:5986. The container's WinRM
# listener uses a self-signed cert generated at build time, which is
# why settings.yaml flips `winrm_server_cert_validation: ignore`.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

$Name = 'patchmgr-windows-vuln'
$Port = if ($env:PORT) { $env:PORT } else { 5986 }

$existing = docker ps -a --format '{{.Names}}' | Where-Object { $_ -eq $Name }
if ($existing) {
    Write-Host "[run] removing existing container $Name"
    docker rm -f $Name | Out-Null
}

Write-Host "[run] starting $Name on 127.0.0.1:$Port"
docker run -d `
    --name $Name `
    --hostname $Name `
    -p "127.0.0.1:${Port}:5986" `
    patchmgr/windows-vuln:ltsc2022 | Out-Null

Write-Host "[run] waiting for WinRM service ..."
for ($i = 1; $i -le 60; $i++) {
    docker exec $Name cmd /c "winrm enumerate winrm/config/Listener" *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[run] WinRM listener is up"
        break
    }
    Start-Sleep -Seconds 2
}

Write-Host "[run] connect with: patchmgr scan --os windows ``"
Write-Host "         --target 127.0.0.1:${Port}:patchadmin:patchadmin ``"
Write-Host "         --settings .\settings.yaml --report-dir .\reports"
Write-Host "[run] stop with:    scripts\stop.ps1"
