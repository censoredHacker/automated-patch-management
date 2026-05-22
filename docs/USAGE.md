# patchmgr — Usage Guide

This document is the operator-facing reference for `patchmgr`. It
covers installation, every CLI subcommand, and per-OS prerequisites.

---

## 1. Installation

```bash
python -m venv .venv
source .venv/Scripts/activate          # Windows: .venv\Scripts\activate

# for Development
pip install -e .

# for Testing
pip install .
```

Verify:

```bash
patchmgr --version
patchmgr --help
```

Optional: copy `.env.example` to `.env` and fill in `NVD_API_KEY` if
you have one (heavily recommended for batch runs — without a key the
NVD endpoint allows ~1 request per 6 seconds).

---

## 2. Target prerequisites

### Linux / AIX targets

* SSH reachable on the configured port (default `22`).
* Either a password or an SSH private key.
* The remote user must have **passwordless** `sudo` for the package
  manager. Example sudoers snippet:

  ```
  %patchmgr ALL=(ALL) NOPASSWD: /usr/bin/dnf, /usr/bin/yum, \
                                /usr/bin/apt-get, /usr/bin/zypper, \
                                /sbin/shutdown, /usr/sbin/shutdown
  ```

* Kernel-level patches will set the *reboot required* flag — plan a
  maintenance window or use `--reboot scheduled`.

### Windows targets

* WinRM listener configured for **HTTPS** on port `5986`. Quick
  bootstrap on the target:

  ```powershell
  winrm quickconfig -transport:https
  Enable-PSRemoting -Force
  New-NetFirewallRule -Name "WinRM-HTTPS" -DisplayName "WinRM HTTPS" `
      -Protocol TCP -LocalPort 5986 -Action Allow
  ```

* The WinRM service certificate must be valid for the host name you
  use in `--target` (or run the tool with
  `winrm_server_cert_validation: ignore` in `settings.yaml` for lab
  environments only).
* The remote account must be a **local Administrator** (or a domain
  admin equivalent).
* The first run will install `PSWindowsUpdate` from the PowerShell
  Gallery into the `CurrentUser` scope of the remote account. The
  target needs outbound HTTPS to `www.powershellgallery.com`.

### AIX targets — UNVERIFIED

The AIX handler has been written from IBM documentation but has not
been validated against real hardware. Always run with `--dry-run`
first, inspect the JSON report, and only then drop the flag in a
controlled lab.

---

## 3. CLI reference

### Common options (every host-running command)

| Flag                | Description |
|---------------------|-------------|
| `--os`              | `linux` \| `windows` \| `aix` |
| `--target`          | `IP:user:pass` (or `IP:port:user:pass`). With `--password-stdin`, drop the password field. |
| `--key PATH`        | SSH private key path (Linux/AIX). |
| `--key-passphrase`  | Optional passphrase for the key. |
| `--password-stdin`  | Read the password from stdin (one line). |
| `--severity-min`    | `low` \| `medium` \| `high` \| `critical` (default `high`). |
| `--timeout N`       | Per-command timeout in seconds (default 600). |
| `--report-dir PATH` | Override `settings.reporting.output_dir`. |
| `--settings PATH`   | YAML settings file. |
| `--log-level`       | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR`. |

### `patchmgr scan`

Discovery + CVE prioritisation, **no remote changes**.

```bash
patchmgr scan --os linux --target 10.0.0.5:admin:hunter2
```

### `patchmgr patch`

Full lifecycle. Adds:

| Flag                 | Description |
|----------------------|-------------|
| `--reboot`           | `auto` \| `scheduled` \| `manual` (default `manual`). |
| `--at HH:MM`         | Required when `--reboot scheduled`. 24-hour clock, host time. |
| `--dry-run/--no-dry-run` | Default `--dry-run`. **Drop the flag explicitly** to actually patch. |

```bash
# Apply only critical patches, schedule reboot for 02:00
patchmgr patch \
    --os linux --target 10.0.0.5:admin:hunter2 \
    --severity-min critical \
    --reboot scheduled --at 02:00 \
    --no-dry-run
```

### `patchmgr batch`

Run scan or patch against an inventory YAML. See
`config/inventory.example.yaml` for the schema.

```bash
patchmgr batch --inventory config/inventory.example.yaml \
               --action patch --no-dry-run
```

### `patchmgr report`

Re-render an existing `report.json` as HTML (handy when you only kept
the JSON).

```bash
patchmgr report --input reports/<run-id>/report.json --format html
```

---

## 4. Reports

Every run creates a directory:

```
reports/<run-id>/
├── report.json     # canonical machine-readable output
├── report.html     # rich human view
└── run.log         # JSON-line structured log
```

Batch runs additionally produce `reports/batch-<id>/summary.json`.

Key fields in `report.json`:

* `metadata.run_id`, `metadata.duration_seconds`
* `target` (host, user, port, auth — never the password)
* `os_info`
* `prioritized_patches[]` with `effective_severity` and CVE list
* `applied_patches[]` with `success`, `error`, trimmed stdout/stderr
* `reboot` — `required`, `mode`, `issued`, `scheduled_at`
* `summary` — `patches_total`, `patches_succeeded`, `patches_failed`,
  `success_rate_percent`

---

## 5. Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success — every patch succeeded (or scan completed). |
| 1 | User / configuration error (bad arguments, missing file, ...). |
| 2 | Partial failure — at least one patch or host failed. |
| 3 | Total failure — could not connect / unrecoverable error. |

Use the exit code in CI / cron to drive alerting.

---

## 6. Troubleshooting

* **`SSH auth failed`** — verify the user/password; keys must be
  unlocked or the passphrase passed via `--key-passphrase`.
* **`could not load PSWindowsUpdate`** — the target cannot reach the
  PowerShell Gallery. Pre-install the module manually:
  `Install-Module PSWindowsUpdate -Scope AllUsers`.
* **NVD HTTP 429** — request an API key or run with
  `--severity-min critical` to reduce the lookup volume.
* **Report directory missing** — pass `--report-dir` or set
  `PATCHMGR_REPORT_DIR` in the environment / `.env` file.
