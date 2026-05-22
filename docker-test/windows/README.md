# Testing patchmgr against a Windows Server Core container

This directory ships everything you need to spin up a Windows Server
Core (LTSC 2022) container that exposes a real **WinRM/HTTPS**
endpoint, point the `patchmgr` CLI at it with `--os windows`, and
watch the scan / patch cycle run end to end.

> ⚠️ The container is intentionally **stale** (no `Install-WindowsUpdate`
> at build time). The compose file binds it to `127.0.0.1` only —
> never edit that line, and never run this image on a host that
> exposes Docker ports to the internet.

> ⚠️ **Windows containers only.** This will not work on Linux/macOS
> hosts and will not work in Docker Desktop's *Linux containers*
> mode. Switch Docker Desktop to "Windows containers" first
> (right-click the tray icon → *Switch to Windows containers...*).

---

## 0. Prerequisites

| Tool                  | Tested with        | Notes |
|-----------------------|--------------------|-------|
| Windows host          | Windows 10/11 Pro, Server 2019/2022 | Hyper-V or process isolation. |
| Docker Desktop        | 24.x or newer, **Windows containers mode** | Compose v2 plugin (`docker compose ...`). |
| Python                | 3.10+              | Same interpreter as the rest of the repo. |
| `patchmgr` installed  | `pip install -e .` from repo root | Adds the `patchmgr` console script. |
| `pywinrm`             | pulled in by `pip install -e .` | Required for the WinRM transport. |

Verify before continuing:

```powershell
docker --version
docker compose version
docker info --format '{{.OSType}}'    # must print "windows"
patchmgr --version
```

If `docker info` prints `linux`, switch Docker Desktop modes first.

---

## 1. Build the test image

From this directory (`docker-test/windows/`):

### Windows PowerShell

```powershell
.\scripts\build.ps1
```

### Git Bash / WSL bash on a Windows host

```bash
chmod +x scripts/*.sh        # one-time
scripts/build.sh
```

Either path is equivalent to:

```powershell
docker build -t patchmgr/windows-vuln:ltsc2022 -f Dockerfile .
```

The build pulls `mcr.microsoft.com/windows/servercore:ltsc2022`
(~2–3 GB on first pull), creates the `patchadmin` local admin
(`password: patchadmin`), generates a self-signed cert, and
configures the WinRM HTTPS listener on port **5986**. It does **not**
run `Install-WindowsUpdate` — that is what makes the image stale
enough for the scanner to find work to do.

---

## 2. Start the container

```powershell
.\scripts\run.ps1                    # PowerShell
# or:
scripts/run.sh                       # Git Bash / WSL
# or:
docker compose up -d --build
```

Either way, WinRM HTTPS ends up listening on **`127.0.0.1:5986`**.
First boot of a Windows container takes ~10–30s while the WinRM
service comes up; `run.ps1` polls until the listener is healthy.

Confirm from the host:

```powershell
docker ps --filter name=patchmgr-windows-vuln
docker exec patchmgr-windows-vuln cmd /c "winrm enumerate winrm/config/Listener"
```

You can also probe with PowerShell from the host (note the
`-SkipCACheck -SkipCNCheck` flags because the cert is self-signed):

```powershell
$cred = Get-Credential patchadmin     # password: patchadmin
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck
Invoke-Command -ComputerName 127.0.0.1 -Port 5986 -UseSSL `
    -Credential $cred -SessionOption $so `
    -ScriptBlock { $PSVersionTable.PSVersion }
```

---

## 3. Run a scan (no changes applied)

From this directory:

```powershell
.\scripts\test-scan.ps1              # PowerShell
# or:
scripts/test-scan.sh                 # Git Bash / WSL
```

Under the hood the script runs:

```powershell
patchmgr scan `
    --os windows `
    --target 127.0.0.1:5986:patchadmin:patchadmin `
    --severity-min medium `
    --settings .\settings.yaml `
    --report-dir .\reports
```

You should see a one-line summary like:

```
host=127.0.0.1 os=windows 10.0.20348 prioritised=N applied=0 ok=0 fail=0 rate=0.0%
reports: reports\<run-id>\report.json, reports\<run-id>\report.html
log:     reports\<run-id>\run.log
```

Open `reports\<run-id>\report.html` in a browser to inspect the
prioritised CVE list with severity bands and per-CVE drill-downs.

> Tip: override the severity floor with the `SEVERITY` env var:
> `$env:SEVERITY='critical'; .\scripts\test-scan.ps1`

---

## 4. Run a patch cycle (dry-run only is recommended)

The patch helper defaults to **dry-run**, so the first invocation is
safe:

```powershell
.\scripts\test-patch.ps1             # dry-run (PowerShell)
scripts/test-patch.sh                # dry-run (bash)
```

> ⚠️ **Real KB installs inside Windows containers are unreliable.**
> Microsoft does not service running containers via Windows Update —
> servicing happens on the host, then a refreshed base image is
> published. Calling `Get-WindowsUpdate -Install` inside the
> container often fails with WUA service errors. The dry-run path
> still proves the discover → prioritise → report → reboot-flag
> pipeline works against a real WinRM endpoint, which is what this
> harness is for.

If you still want to try a real run:

```powershell
.\scripts\test-patch.ps1 -Apply
scripts/test-patch.sh --no-dry-run
```

`--reboot manual` is hard-coded in the helper because the container
cannot really reboot itself.

---

## 5. Stop / clean up

```powershell
.\scripts\stop.ps1                   # PowerShell
scripts/stop.sh                      # bash
# or:
docker compose down
```

Remove the image (a few GB) when you are done:

```powershell
docker image rm patchmgr/windows-vuln:ltsc2022
```

The local NVD cache and report directories live under the repo root
(`reports\`, `%USERPROFILE%\.patchmgr\cache\`) and are independent
of the container lifecycle — delete them by hand if you want a clean
slate.

---

## 6. Common knobs

| Override        | How                                              | Effect |
|-----------------|--------------------------------------------------|--------|
| Container port  | `$env:PORT=5987; .\scripts\run.ps1`              | Bind WinRM to a different host port. Re-export the same `PORT` for the test scripts. |
| Severity floor  | `$env:SEVERITY='critical'; .\scripts\test-scan.ps1` | Skip everything below the chosen level. |
| Settings file   | `$env:SETTINGS='.\my-settings.yaml'; .\scripts\test-scan.ps1` | Point at a different YAML override. |
| Different user  | `$env:USER='patchadmin'; $env:PASS='...'`        | Override the local credential pair. |

---

## 7. Troubleshooting

### `docker build` fails with "no matching manifest for linux/amd64"
You are still in *Linux containers* mode. Right-click Docker Desktop
in the system tray → *Switch to Windows containers...* and re-run
`scripts\build.ps1`.

### `WinRM cannot complete the operation` / `connect: connection refused`
The WinRM service inside the container takes 10–30s to come up after
`docker run`. `run.ps1` polls for up to 2 minutes. If it still fails:

```powershell
docker logs patchmgr-windows-vuln
docker exec patchmgr-windows-vuln cmd /c "winrm enumerate winrm/config/Listener"
```

### `WinRM auth failed` / `the user name or password is incorrect`
NTLM is finicky against `127.0.0.1` in some setups. Try the IP form
explicitly (already what the scripts use), and double-check your
`settings.yaml` has `winrm_server_cert_validation: ignore` because
the cert is self-signed. If you customized `settings.yaml`, also
confirm `inventory.winrm_transport` is `ntlm` (the default).

### `The SSL certificate is signed by an unknown certificate authority`
You are running with `winrm_server_cert_validation: validate` against
a self-signed cert. Use the bundled `settings.yaml` (which sets it to
`ignore`) — that is the whole point of the file.

### NVD `HTTP 429` warnings in the run log
The unauthenticated NVD endpoint allows ~1 request per 6 seconds.
Either set an `NVD_API_KEY` in `.env` (see the project root README)
or run with `--severity-min critical` to cut the lookup volume.

### `Get-WindowsUpdate` returns nothing or hangs
Windows Update Agent (`wuauserv`) is intentionally restricted in
container images. `Get-HotFix` (which the handler also calls) will
still return installed hotfixes, so OS detection and the report
pipeline still work. To prove the install path on a real host you
need a full Windows Server VM, not a container.

---

## 8. What this proves — and what it does not

✅ **Proves**

- `patchmgr` connects to a real WinRM/HTTPS endpoint with NTLM auth.
- Self-signed cert handling via `winrm_server_cert_validation: ignore`
  works end-to-end.
- The Windows handler runs `Get-CimInstance Win32_OperatingSystem`,
  detects `windows`, and parses the JSON correctly.
- `Get-HotFix` enumeration round-trips JSON through pywinrm.
- Discovery, prioritisation, dry-run remediation and JSON + HTML
  reporting all cycle through end-to-end.

❌ **Does not prove**

- Real KB installation. Containers are not serviced by WUA, so the
  `apply_patch` no-dry-run path will frequently fail on the
  `PSWindowsUpdate` install step. Use a Windows Server VM for that.
- Reboot orchestration. The container cannot really reboot itself;
  the helper scripts pin `--reboot manual` for this reason.
- Domain-joined / Kerberos auth. The local `patchadmin` account
  forces NTLM. Domain auth needs a real AD environment.
- Behaviour on Windows Server 2016 / Windows 10 client builds. Only
  LTSC 2022 (Server 2022) is exercised here — earlier versions ship
  different `winrm` quirks (e.g. older `Set-Item WSMan:\` paths).
