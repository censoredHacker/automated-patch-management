# patchmgr — Plain-Language Explainer

This document is for product managers, new engineers joining the
team, and anyone who wants to understand what `patchmgr` does
**before** opening any source files. It deliberately avoids jargon
where possible.

---

## 1. The problem in one paragraph

Every server in a fleet has software with bugs. Some of those bugs
are **security vulnerabilities** (known publicly as "CVEs") and the
operating system vendor has already shipped a fix. The job is to
find every server that is missing a fix, install it, and (when
needed) reboot — without bringing the service down or breaking
anything. Today most teams do this with a mix of spreadsheets, ad-hoc
scripts, and SSH gymnastics. `patchmgr` replaces that with one
predictable command.

---

## 2. What success looks like (the four numbers we care about)

| KPI | What it measures | How patchmgr improves it |
|-----|------------------|--------------------------|
| **Unpatched vulns** | How many known CVEs are still on the fleet? | The `scan` command reports them; `patch` removes them. |
| **Patch success rate** | Of the patches we tried, how many landed? | Retry logic + per-host JSON report makes failures visible. |
| **MTTR** | Mean time from "CVE published" to "fix installed". | `batch` mode runs everything in parallel, no manual orchestration. |
| **Downtime** | Minutes of service outage caused by patching. | `--reboot scheduled --at 02:00` puts reboots in a maintenance window. |

---

## 3. How the tool is organised (the elevator tour)

Think of `patchmgr` as a small assembly line. Each station does one
job and hands the result to the next.

```
   target string                                       JSON / HTML report
   IP:user:pass         +-----------+   +-----------+        on disk
       │                |  Vuln     |   |  Reboot   |          ▲
       ▼                |  intel    |   |  manager  |          │
  +---------+   facts   +-----------+   +-----------+   +-----------+
  | Connect | --------> | Discover  | -> Prioritise -> | Remediate | -> | Report |
  | (SSH /  |           | OS, pkgs, |    by severity   | apply,    |    | writer |
  |  WinRM) |           | missing   |                  | retry,    |    +-----+--+
  +---------+           |  patches  |                  | log       |
                        +-----------+                  +-----------+
```

Each station is one Python sub-package. They talk to each other
through small data classes (a "Credentials", an "OSInfo", a
"MissingPatch", and so on) — never through global state. That means
we can replace any station — for instance, swap the public NVD feed
for an internal Tenable export — without touching the others.

---

## 4. The CLI in three sentences

* `patchmgr scan` looks at a host and tells you what is missing.
  Nothing changes on the host.
* `patchmgr patch` does the same and then installs the missing
  pieces, optionally rebooting.
* `patchmgr batch` runs either of the above against a YAML list of
  hosts.

Every run produces a folder under `reports/` with a JSON file (for machines), an HTML file (for humans), and a structured log.

---

## 5. Things we deliberately did not build (yet)

| Not built | Why | What you can do instead |
|-----------|-----|-------------------------|
| Web dashboard / UI | Kept scope small for v1; the JSON report is enough to feed Splunk/Grafana. | Pipe `report.json` files into your existing observability stack. |
| Automatic rollback | Hard to do reliably across all OSes; risky to do partially. | Each patch ID is recorded so an operator can run `yum history undo` etc. |
| Agent on the host | Adds another moving part to maintain and audit. | We use the OS's existing remote-management surface (SSH / WinRM). |
| Custom CVE ingestion | NVD covers ~95% of cases out of the box. | The `vulnsource` package has a clean interface — adding Tenable / Qualys is a single new file. |

---

## 6. Operational profile

* **Where it runs:** any laptop or jump-box with Python 3.10+ and
  network reachability to the targets.
* **What it touches:** read on the local filesystem (`reports/`,
  cache, `.env`); read+exec on remote hosts.
* **What it stores long-term:** the on-disk NVD cache and the run
  reports. Nothing else.
* **Failure mode:** every operation is restart-safe. A killed run
  leaves a partial report behind; the next run starts fresh.

---

## 7. Glossary

* **CVE** — *Common Vulnerabilities and Exposures*. A unique ID for
  one known software bug with security impact.
* **CVSS** — *Common Vulnerability Scoring System*. A 0-10 number
  that says how bad a CVE is. We bucket it into Low / Medium / High /
  Critical.
* **NVD** — *National Vulnerability Database*. The canonical public
  source of CVE data, run by NIST.
* **WinRM** — Microsoft's remote management protocol. Same
  conceptual role as SSH but for Windows.
* **MTTR** — *Mean Time To Remediate*. How long it takes, on
  average, between learning about a vulnerability and having the
  fleet patched.

---

## 8. One-page demo script (for stakeholder reviews)

1. Show `patchmgr scan` against a deliberately-stale Ubuntu VM.
2. Open the generated `report.html` — point at the severity bands
   and the CVE expand boxes.
3. Run `patchmgr patch --severity-min critical --no-dry-run`.
4. Re-run `scan` — show the fleet's CVE count drop.
5. Bring up `report.json` and explain how it plugs into the
   existing SIEM.

That cycle takes about five minutes and tells the full story without any code on screen.
