# patchmgr — Security Notes

`patchmgr` is a privileged tool: by design it can authenticate to
servers, install software, and reboot them. This document captures
the threat model, the controls already implemented, and the
operational practices we expect users to follow.

---

## 1. Threat model

| Asset | Threat | Mitigation |
|-------|--------|-----------|
| Remote host credentials | Stolen via logs / reports | Redaction filter on every log handler, credentials never serialised into reports. |
| In-flight commands | MITM / sniffing | SSH host-key verification (`RejectPolicy`); WinRM forced to HTTPS with cert validation. |
| Patch supply chain | Tampered packages | Tool relies on the OS package manager's signature verification (yum/dnf/apt/zypper/installp). Disabling verification is **not** supported. |
| Operator workstation | Local secret leak via shell history | `--password-stdin` and `.env` support; `IP:user:pass` discouraged for production runs. |
| Malicious remote stdout | Log injection / report XSS | Jinja2 autoescape on the HTML template; logs are written via `logging` (no `print`). |

Out of scope: physical attacks on the operator workstation,
compromise of the OS package mirror, weaknesses in the upstream
patches themselves.

---

## 2. Implemented controls

### Encrypted communication
* **SSH:** paramiko default ciphers; protocol 2 only; host key
  verification on (`set_missing_host_key_policy(RejectPolicy)`).
  `--insecure-host-key` exists for lab use and emits a `WARNING`.
* **WinRM:** defaults to `https://<host>:5986/wsman` with
  `server_cert_validation=validate`. HTTP transport is possible but
  emits a loud `WARNING` and is never auto-selected.

### Credential hygiene
* `RedactingFilter` scrubs `IP:user:pass`, `password=…`, `token=…`,
  `Authorization: …` patterns from every log record (including
  `LogRecord.args`, in case a caller passes the secret as a format
  argument).
* `Credentials.__repr__` / `__str__` only emit `user@host:port`.
* `Credentials.safe_dict()` is the only thing the reporting layer
  ever sees — no field named `password` is in the data class output.

### Privilege boundaries
* The tool runs unprivileged locally. Privilege escalation happens on
  the remote host via `sudo -n` (Linux/AIX) or the remote
  Administrator (Windows).
* Sudo is non-interactive (`-n`): if passwordless sudo is not
  configured, the tool fails fast rather than prompting.

### Input validation
* Pydantic validates settings and inventory schemas; `extra="forbid"`
  catches typos.
* Targets parsed by `parse_target()` validate IP / hostname syntax
  and port range.
* Shell commands always go through `sh_quote` / `ps_quote` —
  user-supplied values never reach `bash -c` unquoted.

### Resilience
* `tenacity` retry on transient network failures (default 3 attempts,
  exponential backoff capped at 30s).
* Per-command and per-connect timeouts — no hung session can wedge
  the tool.

---

## 3. Operational guidance

* **Never** commit a real `.env` to source control. The provided
  `.gitignore` excludes it, but a pre-commit hook (`detect-secrets`,
  `gitleaks`) is strongly recommended.
* Prefer SSH keys over passwords. Store them on disk with `0600`
  permissions and protect them with a passphrase + agent.
* Prefer a secrets manager for inventory passwords (HashiCorp Vault,
  AWS Secrets Manager, Windows Credential Manager). Inject values
  into the environment at run-time and reference them as `${VAR}` in
  the inventory YAML.
* Rotate the SSH key / Administrator password used by patchmgr on the
  same cadence as your other privileged credentials.
* Pin the tool version in your runner (`pip install patchmgr==…`) so
  CI can detect unexpected upgrades.
* Run with `--severity-min critical` in production until you have
  built confidence in the prioritisation; lower the bar in stages.

---

## 4. Known limitations

* **Rollback:** patchmgr does not roll back failed patches. Each
  installed patch ID is recorded in the report so a manual rollback
  is possible (`yum history undo`, `Remove-WindowsUpdate`, ...).
* **AIX:** the handler is unverified on real hardware. Treat any AIX
  run with `--no-dry-run` as experimental.
* **Concurrent runs:** running two `patchmgr patch` invocations
  against the same host simultaneously can confuse the package
  manager. The CLI does not enforce a lock.

---

## 5. Reporting a security issue

Please do not file public GitHub issues for security problems.
Email `security@example.invalid` with details and a proof of concept
where possible. We aim to triage within 2 business days.
