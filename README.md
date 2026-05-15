# patchmgr — Automated Patch Management CLI

`patchmgr` is a cross-platform, **agentless** command-line tool that remotely
discovers, prioritises, and remediates OS-level vulnerabilities on **Linux**,
**Windows**, and **AIX** hosts.

It talks to remote hosts over SSH (Linux/AIX) or WinRM over HTTPS (Windows),
correlates installed packages against CVE intelligence from the **NVD 2.0
REST API**, and applies patches using the host's native package manager
(`yum`/`dnf`/`apt`/`zypper`, Windows Update via `PSWindowsUpdate`,
`installp`/`instfix` on AIX).

```
                     +----------------------+
                     |       CLI (click)    |
                     +----------+-----------+
                                |
                +---------------+---------------+
                |                               |
        +-------v-------+               +-------v-------+
        |  Transport    |               | Vuln Source   |
        |  SSH / WinRM  |               |  NVD / local  |
        +-------+-------+               +-------+-------+
                |                               |
        +-------v-------+               +-------v-------+
        |  Discovery    +-------------->+  Prioritizer  |
        +-------+-------+               +-------+-------+
                |                               |
        +-------v-------+               +-------v-------+
        |   OS Handler  +<--------------+  Remediator   |
        | linux/win/aix |               +-------+-------+
        +-------+-------+                       |
                |                       +-------v-------+
                +---------------------->+   Reporting   |
                                        |  JSON / HTML  |
                                        +---------------+
```

## Install

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .
```

## Quickstart

```bash
# 1. Scan a single Linux host (no changes made)
patchmgr scan --os linux --target 10.0.0.11:admin:S3cret!

# 2. Apply only Critical/High patches and schedule a reboot
patchmgr patch \
    --os linux \
    --target 10.0.0.11:admin:S3cret! \
    --severity-min high \
    --reboot scheduled --at "02:00"

# 3. Batch run from inventory
patchmgr batch --inventory config/inventory.example.yaml --action patch --dry-run
```

Reports land under `./reports/<run-id>/` as `report.json`, `report.html`,
and `run.log`.

## Documentation

- [`docs/USAGE.md`](docs/USAGE.md) — full CLI reference and per-OS examples
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model & hardening guide
- [`docs/EXPLAINER.md`](docs/EXPLAINER.md) — plain-language overview for
  product managers and new developers

## Status & limitations

| OS      | Discovery | Remediation | Tested |
|---------|-----------|-------------|--------|
| Linux   | yes       | yes         | yes    |
| Windows | yes       | yes         | yes    |
| AIX     | yes       | yes         | **no — dry-run by default** |

AIX handlers follow IBM documentation but have **not** been validated on
real hardware. Keep `dry_run: true` for AIX unless you have a test LPAR.

## License

All rights are reserved by Gaurav Satija.
