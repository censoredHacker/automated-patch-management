"""Command-line entrypoint for ``patchmgr``.

Subcommands:

* ``scan``   — discovery + prioritisation, no changes applied
* ``patch``  — full lifecycle (discover, prioritise, remediate, reboot)
* ``batch``  — run ``scan`` or ``patch`` against an inventory YAML
* ``report`` — re-render an existing report.json into HTML

Exit codes:
    0  success
    1  user / configuration error (bad arguments, missing file, ...)
    2  partial failure — at least one host or patch failed
    3  total failure — could not connect / unrecoverable error
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Optional

import click
from dotenv import load_dotenv

from patchmgr import __version__
from patchmgr.config import (
    Inventory,
    InventoryHost,
    Settings,
)
from patchmgr.credentials import CredentialParseError, Credentials, parse_target
from patchmgr.engine.runner import RunOptions, run_patch, run_scan
from patchmgr.logging_setup import configure_logging, get_logger
from patchmgr.reporting import HostReport, write_reports
from patchmgr.reporting.writer import write_aggregate
from patchmgr.transport import TransportConnectionError, TransportError


# ---------------------------------------------------------------------------
# Shared CLI option helpers
# ---------------------------------------------------------------------------
SEVERITIES = ("low", "medium", "high", "critical")
OS_TYPES = ("linux", "windows", "aix")
REBOOT_MODES = ("auto", "scheduled", "manual")


def _common_options(f):
    """Attach options that every host-running command shares."""
    f = click.option("--os", "os_type", type=click.Choice(OS_TYPES), required=True,
                     help="Target operating system type.")(f)
    f = click.option("--target", "target_str", required=True, metavar="IP:USER:PASS",
                     help="Target host. Password may be replaced with '-' to "
                          "read from stdin.")(f)
    f = click.option("--key", "key_path", type=click.Path(dir_okay=False),
                     default=None,
                     help="SSH private key path (Linux/AIX).")(f)
    f = click.option("--key-passphrase", "key_passphrase", default=None,
                     help="Optional passphrase for the SSH private key.")(f)
    f = click.option("--severity-min",
                     type=click.Choice(SEVERITIES), default="high",
                     show_default=True,
                     help="Drop patches below this severity.")(f)
    f = click.option("--timeout", type=click.IntRange(1), default=600,
                     show_default=True,
                     help="Per-command timeout in seconds.")(f)
    f = click.option("--password-stdin", is_flag=True, default=False,
                     help="Read password from stdin instead of the target string.")(f)
    f = click.option("--report-dir", type=click.Path(file_okay=False),
                     default=None,
                     help="Override settings.reporting.output_dir.")(f)
    f = click.option("--settings", "settings_path", type=click.Path(dir_okay=False),
                     default=None,
                     help="Path to a YAML settings file (optional).")(f)
    f = click.option("--log-level",
                     type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
                     default="INFO", show_default=True)(f)
    return f


def _resolve_credentials(
    target_str: str,
    *,
    password_stdin: bool,
    key_path: Optional[str],
    key_passphrase: Optional[str],
    default_port: int,
) -> Credentials:
    """Build :class:`Credentials` from a target string, honouring stdin."""
    if password_stdin:
        password = sys.stdin.readline().rstrip("\n")
        if ":" not in target_str or target_str.count(":") < 1:
            raise click.UsageError(
                "with --password-stdin, --target must be IP:username "
                "(no password field)"
            )
        host, username = target_str.split(":", 1)
        target_str = f"{host}:{username}:{password}"

    try:
        return parse_target(
            target_str,
            default_port=default_port,
            key_path=key_path,
            key_passphrase=key_passphrase,
        )
    except CredentialParseError as e:
        raise click.UsageError(f"invalid --target: {e}") from e


def _load_settings(
    path: Optional[str], *, log_level: str, report_dir: Optional[str]
) -> Settings:
    settings = Settings.load(Path(path) if path else None)
    settings.logging.level = log_level
    if report_dir:
        settings.reporting.output_dir = Path(report_dir)
    return settings


def _setup_logging(settings: Settings, run_id: str) -> Path:
    """Wire up logging and return the per-run log file path."""
    log_dir = settings.reporting.output_dir / run_id
    log_file = log_dir / "run.log"
    configure_logging(
        log_file=log_file,
        level=settings.logging.level,
        json_file=settings.logging.json_format,
        console=settings.logging.console,
    )
    return log_file


def _summary_line(report: HostReport) -> str:
    s = report.to_dict()["summary"]
    return (
        f"host={report.target.get('host')} "
        f"os={report.os_info.get('distro')} {report.os_info.get('version')} "
        f"prioritised={len(report.prioritized_patches)} "
        f"applied={s['patches_total']} "
        f"ok={s['patches_succeeded']} fail={s['patches_failed']} "
        f"rate={s['success_rate_percent']}%"
    )


# ---------------------------------------------------------------------------
# Click groups & commands
# ---------------------------------------------------------------------------
@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="patchmgr")
def cli() -> None:
    """Cross-platform automated patch management."""
    # Load .env early so option defaults can read environment variables.
    load_dotenv(override=False)


# ----------------------- scan ---------------------------------------------
@cli.command()
@_common_options
def scan(
    os_type: str,
    target_str: str,
    key_path: Optional[str],
    key_passphrase: Optional[str],
    severity_min: str,
    timeout: int,
    password_stdin: bool,
    report_dir: Optional[str],
    settings_path: Optional[str],
    log_level: str,
) -> None:
    """Discover and prioritise patches on a single host. No changes applied."""
    settings = _load_settings(settings_path, log_level=log_level, report_dir=report_dir)
    creds = _resolve_credentials(
        target_str,
        password_stdin=password_stdin,
        key_path=key_path,
        key_passphrase=key_passphrase,
        default_port=22 if os_type in ("linux", "aix") else 5986,
    )
    run_id = str(uuid.uuid4())
    log_file = _setup_logging(settings, run_id)
    log = get_logger("patchmgr.cli")
    log.info("starting scan run-id=%s target=%s", run_id, creds)

    opts = RunOptions(
        os_type=os_type,
        credentials=creds,
        severity_min=severity_min,  # type: ignore[arg-type]
        reboot_mode="manual",
        dry_run=True,
        timeout=timeout,
    )
    try:
        report = run_scan(opts, settings)
        report.metadata.run_id = run_id  # use the run-id we picked above
    except (TransportConnectionError, TransportError) as e:
        log.error("scan failed: %s", e)
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(3)
    written = write_reports(
        report,
        output_dir=settings.reporting.output_dir,
        formats=settings.reporting.formats,
    )
    click.echo(_summary_line(report))
    click.echo(f"reports: {', '.join(str(p) for p in written.values())}")
    click.echo(f"log:     {log_file}")


# ----------------------- patch --------------------------------------------
@cli.command()
@_common_options
@click.option("--reboot", "reboot_mode", type=click.Choice(REBOOT_MODES),
              default="manual", show_default=True,
              help="What to do if the host requests a reboot.")
@click.option("--at", "reboot_at", default=None, metavar="HH:MM",
              help="Time of day for --reboot scheduled (24h clock).")
@click.option("--dry-run/--no-dry-run", default=True, show_default=True,
              help="Run end-to-end without actually applying changes.")
def patch(
    os_type: str,
    target_str: str,
    key_path: Optional[str],
    key_passphrase: Optional[str],
    severity_min: str,
    timeout: int,
    password_stdin: bool,
    report_dir: Optional[str],
    settings_path: Optional[str],
    log_level: str,
    reboot_mode: str,
    reboot_at: Optional[str],
    dry_run: bool,
) -> None:
    """Discover, prioritise, and remediate vulnerabilities on a single host."""
    if reboot_mode == "scheduled" and not reboot_at:
        raise click.UsageError("--reboot scheduled requires --at HH:MM")

    settings = _load_settings(settings_path, log_level=log_level, report_dir=report_dir)
    creds = _resolve_credentials(
        target_str,
        password_stdin=password_stdin,
        key_path=key_path,
        key_passphrase=key_passphrase,
        default_port=22 if os_type in ("linux", "aix") else 5986,
    )
    run_id = str(uuid.uuid4())
    log_file = _setup_logging(settings, run_id)
    log = get_logger("patchmgr.cli")
    log.info("starting patch run-id=%s target=%s dry_run=%s", run_id, creds, dry_run)

    # AIX safety net: refuse a real run unless the operator passed --no-dry-run.
    if os_type == "aix" and not dry_run:
        log.warning("AIX handler is unverified on real hardware — proceeding "
                    "because --no-dry-run was passed explicitly")

    opts = RunOptions(
        os_type=os_type,
        credentials=creds,
        severity_min=severity_min,  # type: ignore[arg-type]
        reboot_mode=reboot_mode,    # type: ignore[arg-type]
        reboot_at=reboot_at,
        dry_run=dry_run,
        timeout=timeout,
    )
    try:
        report = run_patch(opts, settings)
        report.metadata.run_id = run_id
    except (TransportConnectionError, TransportError) as e:
        log.error("patch failed: %s", e)
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(3)

    written = write_reports(
        report,
        output_dir=settings.reporting.output_dir,
        formats=settings.reporting.formats,
    )
    click.echo(_summary_line(report))
    click.echo(f"reports: {', '.join(str(p) for p in written.values())}")
    click.echo(f"log:     {log_file}")
    if report.patches_failed:
        sys.exit(2)


# ----------------------- batch --------------------------------------------
@cli.command()
@click.option("--inventory", required=True, type=click.Path(exists=True, dir_okay=False),
              help="YAML inventory file describing the hosts.")
@click.option("--action", type=click.Choice(["scan", "patch"]), default="scan",
              show_default=True)
@click.option("--dry-run/--no-dry-run", default=True, show_default=True)
@click.option("--settings", "settings_path", type=click.Path(dir_okay=False),
              default=None)
@click.option("--report-dir", type=click.Path(file_okay=False), default=None)
@click.option("--log-level",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO", show_default=True)
def batch(
    inventory: str,
    action: str,
    dry_run: bool,
    settings_path: Optional[str],
    report_dir: Optional[str],
    log_level: str,
) -> None:
    """Run ``scan`` or ``patch`` against every host in an inventory file."""
    settings = _load_settings(settings_path, log_level=log_level, report_dir=report_dir)
    aggregate_id = str(uuid.uuid4())[:8]
    log_file = _setup_logging(settings, f"batch-{aggregate_id}")
    log = get_logger("patchmgr.cli")

    try:
        inv = Inventory.load(Path(inventory))
    except Exception as e:  # noqa: BLE001
        click.echo(f"ERROR loading inventory: {e}", err=True)
        sys.exit(1)

    log.info("loaded %d hosts from %s", len(inv.hosts), inventory)
    reports: list[HostReport] = []
    failures = 0

    for host in inv.hosts:
        eff = inv.effective(host)
        port_default = host.port or (22 if host.os in ("linux", "aix") else 5986)
        try:
            creds = Credentials(
                host=host.address,
                username=host.username,
                password=host.password,
                key_path=host.key_path,
                key_passphrase=host.key_passphrase,
                port=port_default,
            )
        except CredentialParseError as e:
            log.error("inventory host %s invalid: %s", host.name, e)
            failures += 1
            continue

        opts = RunOptions(
            os_type=host.os,
            credentials=creds,
            severity_min=eff["severity_min"],   # type: ignore[arg-type]
            reboot_mode=eff["reboot"],           # type: ignore[arg-type]
            reboot_at=None,
            dry_run=bool(eff["dry_run"]) or dry_run,
            timeout=int(eff["timeout"]),         # type: ignore[arg-type]
            winrm_transport=host.winrm_transport,
            winrm_verify_ssl=host.winrm_verify_ssl,
        )
        log.info("=== host %s (%s) ===", host.name, host.address)
        try:
            report = (
                run_patch(opts, settings) if action == "patch"
                else run_scan(opts, settings)
            )
        except (TransportConnectionError, TransportError) as e:
            log.error("host %s unreachable: %s", host.name, e)
            failures += 1
            continue
        except Exception as e:  # noqa: BLE001 - never crash the whole batch
            log.exception("host %s raised", host.name)
            failures += 1
            continue

        write_reports(
            report,
            output_dir=settings.reporting.output_dir,
            formats=settings.reporting.formats,
        )
        click.echo(_summary_line(report))
        if report.patches_failed:
            failures += 1
        reports.append(report)

    summary_path = write_aggregate(
        reports,
        output_dir=settings.reporting.output_dir,
        aggregate_id=aggregate_id,
    )
    click.echo(f"batch summary: {summary_path}")
    click.echo(f"log:           {log_file}")
    if failures:
        sys.exit(2)


# ----------------------- report -------------------------------------------
@cli.command()
@click.option("--input", "input_path", required=True,
              type=click.Path(exists=True, dir_okay=False),
              help="Path to an existing report.json file.")
@click.option("--format", "fmt", type=click.Choice(["html", "json"]),
              default="html", show_default=True)
def report(input_path: str, fmt: str) -> None:
    """Re-render an existing JSON report."""
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))
    if fmt == "json":
        click.echo(json.dumps(data, indent=2))
        return
    # Render HTML next to the input file.
    out = Path(input_path).with_name("report.html")
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    env = Environment(
        loader=FileSystemLoader(
            str(Path(__file__).parent / "reporting" / "templates")
        ),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True, lstrip_blocks=True,
    )
    out.write_text(
        env.get_template("report.html.j2").render(report=data),
        encoding="utf-8",
    )
    click.echo(f"wrote {out}")


# ---------------------------------------------------------------------------
# Programmatic entry point referenced by `patchmgr` console script.
# ---------------------------------------------------------------------------
def main() -> None:
    try:
        cli(standalone_mode=False)
    except click.UsageError as e:
        click.echo(f"USAGE ERROR: {e.format_message()}", err=True)
        sys.exit(1)
    except click.Abort:
        click.echo("aborted", err=True)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        logging.getLogger("patchmgr").exception("unhandled error")
        click.echo(f"FATAL: {e}", err=True)
        sys.exit(3)


if __name__ == "__main__":  # pragma: no cover
    main()
