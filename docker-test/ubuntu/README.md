# Testing patchmgr against a vulnerable Ubuntu container

This directory ships everything you need to spin up a deliberately
**stale** Ubuntu 20.04 (focal) container, point the `patchmgr` CLI at
it over SSH, and watch a real `scan` / `patch` cycle end-to-end.

> ⚠️ The container is intentionally **vulnerable**. The compose file
> binds it to `127.0.0.1` only — never edit that line, and never run
> this image on a host that exposes Docker ports to the internet.

---

## 0. Prerequisites

| Tool                  | Tested with        | Notes |
|-----------------------|--------------------|-------|
| Docker Desktop / Engine | 24.x or newer    | Compose v2 plugin (`docker compose ...`). |
| Python                | 3.10+              | Same interpreter you use for the rest of the repo. |
| `patchmgr` installed   | `pip install -e .` from repo root | Adds the `patchmgr` console script. |

Verify before continuing:

```bash
docker --version
docker compose version
patchmgr --version
```

---

## 1. Build the test image

From this directory (`docker-test/ubuntu/`):

### Linux / macOS / WSL

```bash
chmod +x scripts/*.sh        # one-time
scripts/build.sh
```

### Windows PowerShell

```powershell
.\scripts\build.ps1
```

Either path is equivalent to:

```bash
docker build -t patchmgr/ubuntu-vuln:focal -f Dockerfile .
```

The build pulls `ubuntu:20.04`, installs `openssh-server` + `sudo`,
creates the `patchadmin` user (`password: patchadmin`, passwordless
`sudo` for the package manager), and **does not** run `apt-get
upgrade` — that is what makes the image stale enough for the scanner
to find work to do.

---

## 2. Start the container

```bash
scripts/run.sh                       # bash
.\scripts\run.ps1                    # PowerShell
# or:
docker compose up -d --build
```

Either way, sshd ends up listening on **`127.0.0.1:2222`**. Confirm:

```bash
docker ps --filter name=patchmgr-ubuntu-vuln
ssh -p 2222 patchadmin@127.0.0.1     # password: patchadmin
exit
```

The first `ssh` connection will ask you to trust the host key — that
is expected because the image generates a fresh key on every build.
The bundled `settings.yaml` already disables strict host-key checking
for this test, so `patchmgr` itself does not need that prompt.

---

## 3. Run a scan (no changes applied)

From this directory:

```bash
scripts/test-scan.sh                 # bash
.\scripts\test-scan.ps1              # PowerShell
```

Under the hood the script runs:

```bash
patchmgr scan \
    --os linux \
    --target 127.0.0.1:2222:patchadmin:patchadmin \
    --severity-min medium \
    --settings ./settings.yaml \
    --report-dir ./reports
```

You should see a one-line summary like:

```
host=127.0.0.1 os=ubuntu 20.04 prioritised=37 applied=0 ok=0 fail=0 rate=0.0%
reports: reports\<run-id>\report.json, reports\<run-id>\report.html
log:     reports\<run-id>\run.log
```

Open `reports/<run-id>/report.html` in a browser to inspect the
prioritised CVE list with severity bands and per-CVE drill-downs.

> Tip: override the severity floor with the `SEVERITY` env var:
> `SEVERITY=critical scripts/test-scan.sh`

---

## 4. Run a patch cycle

The patch helper defaults to **dry-run**, so the first invocation is
safe:

```bash
scripts/test-patch.sh                # dry-run
.\scripts\test-patch.ps1             # dry-run (PowerShell)
```

Once you are happy with the dry-run output, install the patches for
real:

```bash
scripts/test-patch.sh --no-dry-run                 # bash
.\scripts\test-patch.ps1 -Apply                    # PowerShell
```

Re-running `scripts/test-scan.sh` afterwards should show the
prioritised list shrink — that is the whole product loop in 30 seconds.

`--reboot manual` is hard-coded in the helper because the container
cannot really reboot itself; the report will still flag whether a
reboot *would* have been needed on a real host.

---

## 5. Stop / clean up

```bash
scripts/stop.sh                      # bash
.\scripts\stop.ps1                   # PowerShell
# or:
docker compose down
```

Remove the image when you are done:

```bash
docker image rm patchmgr/ubuntu-vuln:focal
```

The local NVD cache and report directories live under the repo root
(`reports/`, `~/.patchmgr/cache/`) and are independent of the
container lifecycle — delete them by hand if you want a clean slate.

---

## 6. Common knobs

| Override | How | Effect |
|----------|-----|--------|
| Container port | `PORT=2223 scripts/run.sh` | Bind sshd to a different host port. Re-export the same `PORT` for the test scripts. |
| Severity floor | `SEVERITY=critical scripts/test-scan.sh` | Skip everything below the chosen level. |
| Settings file | `SETTINGS=./my-settings.yaml scripts/test-scan.sh` | Point at a different YAML override. |
| Custom SSH key | drop the public key into `authorized_keys` before `build.sh` | Enables key-based login as `patchadmin`. |

---

## 7. Troubleshooting

### `ssh: Connection refused`
Wait a few seconds — sshd needs ~1–2s to come up after `docker run`.
The `run.sh` script polls `pgrep sshd` for up to 15 seconds and exits
when sshd is ready. If the message persists, check `docker logs
patchmgr-ubuntu-vuln`.

### `Host key verification failed`
You set `ssh_strict_host_key_checking: true` in your settings, or you
copied the file from elsewhere. Use the bundled `settings.yaml`, or
rebuild the image to refresh the host key and clear your
`~/.ssh/known_hosts` entry for `[127.0.0.1]:2222`.

### `sudo: a password is required`
You overrode `Defaults` in `/etc/sudoers` somewhere or rebuilt the
image with a different user. Confirm `/etc/sudoers.d/patchadmin`
inside the container reads `NOPASSWD`:

```bash
docker exec patchmgr-ubuntu-vuln cat /etc/sudoers.d/patchadmin
```

### NVD `HTTP 429` warnings in the run log
The unauthenticated NVD endpoint allows ~1 request per 6 seconds.
Either set an `NVD_API_KEY` in `.env` (see the project root README)
or run with `--severity-min critical` to cut the lookup volume.

### Scan finds zero patches
The base image was either rebuilt very recently or has no security
updates yet. Force the issue with:

```bash
docker exec patchmgr-ubuntu-vuln \
    apt-get install -y --no-install-recommends openssl=1.1.1f-1ubuntu2
```

then re-run the scan (this downgrades a single package so the next
`apt-get upgrade` will have something to do).

---

## 8. What this proves — and what it does not

✅ **Proves**

- `patchmgr` connects to a real SSH server, authenticates, and
  detects Ubuntu correctly.
- The Linux handler picks the right package manager (`apt`).
- Discovery, prioritisation, and remediation cycle through end-to-end
  with retries, JSON + HTML reporting, and structured logs.
- The dry-run / no-dry-run split actually behaves differently.

❌ **Does not prove**

- Behaviour against RHEL / SUSE / AIX / Windows. Those need their
  own targets — the Linux handler covers `dnf` / `yum` / `zypper`,
  but they are exercised only by unit tests with mocked output.
- Reboot orchestration on a real host. The container cannot reboot
  itself; the helper scripts pin `--reboot manual` for this reason.
- Operator workflow against a fleet larger than one host. For that,
  swap to `patchmgr batch --inventory ...` with the example
  inventory in `config/inventory.example.yaml`.
