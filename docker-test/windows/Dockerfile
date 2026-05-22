# escape=`
FROM mcr.microsoft.com/windows/servercore:ltsc2022

SHELL ["powershell", "-NoLogo", "-NoProfile", "-Command", "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue';"]

# ---------------------------------------------------------------------------
# Local 'patchadmin' user with admin rights. NTLM auth from pywinrm
# requires a real local account; the SAM database in Server Core is
# empty by default.
# ---------------------------------------------------------------------------
RUN $pwd = ConvertTo-SecureString 'SuperSecret2026!' -AsPlainText -Force; `
    New-LocalUser -Name 'patchadmin' -Password $pwd -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword | Out-Null; `
    Add-LocalGroupMember -Group 'Administrators' -Member 'patchadmin'

# ---------------------------------------------------------------------------
# WinRM HTTPS listener on 5986 with a self-signed cert.
#
# The patchmgr runner hard-codes scheme="https" for Windows targets,
# so plain HTTP/5985 will not work. The bundled settings.yaml sets
# `winrm_server_cert_validation: ignore` because the cert is, by
# definition, untrusted.
#
# We also widen WinRM service quotas (MaxMemoryPerShellMB, idle
# timeout) because PSWindowsUpdate's first run is memory-hungry, and
# enable Negotiate (NTLM) auth which is what pywinrm uses by default.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Configure WinRM service and wait for it to be fully ready
# ---------------------------------------------------------------------------
RUN Set-Service -Name WinRM -StartupType Automatic; `
    Start-Service WinRM; `
    while ((Get-Service WinRM).Status -ne 'Running') { Start-Sleep -Seconds 1 }
 
# ---------------------------------------------------------------------------
# Clean up any default HTTP listeners once WSMan provider is mounted
# ---------------------------------------------------------------------------
RUN while (-not (Test-Path WSMan:\localhost)) { Start-Sleep -Seconds 1 }; `
    if (Test-Path WSMan:\localhost\Listener) { `
        Get-ChildItem -Path WSMan:\localhost\Listener\ | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue `
    }
 
# ---------------------------------------------------------------------------
# Generate certificate and create the HTTPS listener on port 5986
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Generate certificate and create the HTTPS listener on port 5986
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Generate certificate and create the HTTPS listener on port 5986
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Generate certificate and create the HTTPS listener on port 5986 natively
# ---------------------------------------------------------------------------
RUN $cert = New-SelfSignedCertificate `
        -DnsName 'localhost','patchmgr-windows-vuln' `
        -CertStoreLocation Cert:\LocalMachine\My `
        -NotAfter (Get-Date).AddYears(5) `
        -KeyExportPolicy NonExportable `
        -KeyUsage DigitalSignature,KeyEncipherment `
        -Type SSLServerAuthentication; `
    $thumb = $cert.Thumbprint; `
    New-WSManInstance -ResourceURI 'winrm/config/Listener' `
        -SelectorSet @{Address='*';Transport='HTTPS'} `
        -ValueSet @{Hostname='localhost';CertificateThumbprint=$thumb}
    
# ---------------------------------------------------------------------------
# Harden and tune WinRM service settings
# ---------------------------------------------------------------------------
RUN Set-Item -Path WSMan:\localhost\Service\Auth\Basic    -Value $true; `
    Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true; `
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false; `
    Set-Item -Path WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value 1024; `
    Set-Item -Path WSMan:\localhost\Shell\IdleTimeout -Value 7200000

# ---------------------------------------------------------------------------
# Smoke-test the listener at build time so a broken cert/listener
# trips the build instead of the test run.
# ---------------------------------------------------------------------------
RUN cmd /c "winrm enumerate winrm/config/Listener" | Out-Host

EXPOSE 5986

# ---------------------------------------------------------------------------
# WinRM is a background service, so the container needs an explicit
# foreground process to stay alive. We start the service (idempotent
# if it is already auto-started) and then sleep forever.
# ---------------------------------------------------------------------------
CMD ["powershell", "-NoLogo", "-NoProfile", "-Command", "Start-Service WinRM; Write-Host '[entrypoint] WinRM HTTPS listening on 5986'; while ($true) { Start-Sleep -Seconds 3600 }"]