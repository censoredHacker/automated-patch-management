"""Top-level run orchestration — wires every component together.

Two public entry points:

* :func:`run_scan`  — discover + prioritise (no changes applied).
* :func:`run_patch` — discover + prioritise + remediate + reboot.

Both produce a :class:`patchmgr.reporting.models.HostReport` which
the CLI then hands to the reporting layer.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from patchmgr.config import RebootMode, Severity, Settings
from patchmgr.credentials import Credentials
from patchmgr.engine.discovery import discover
from patchmgr.engine.prioritizer import prioritize
from patchmgr.engine.reboot import handle_reboot
from patchmgr.engine.remediator import apply_all
from patchmgr.handlers import build_handler
from patchmgr.reporting.models import HostReport, RunMetadata
from patchmgr.transport import Transport
from patchmgr.transport.ssh import SSHTransport
from patchmgr.transport.winrm import WinRMTransport
from patchmgr.vulnsource import build_vuln_source


logger = logging.getLogger(__name__)


@dataclass
class RunOptions:
    """Per-host runtime knobs passed in from the CLI / batch loader."""

    os_type: str
    credentials: Credentials
    severity_min: Severity = "high"
    reboot_mode: RebootMode = "manual"
    reboot_at: Optional[str] = None
    dry_run: bool = True
    timeout: int = 600
    winrm_transport: str = "ntlm"
    winrm_verify_ssl: bool = True


def _make_transport(opts: RunOptions, settings: Settings) -> Transport:
    """Pick SSH or WinRM based on the requested OS."""
    if opts.os_type in ("linux", "aix"):
        return SSHTransport(
            opts.credentials,
            connect_timeout=settings.network.connect_timeout_seconds,
            command_timeout=opts.timeout,
            strict_host_key_checking=settings.network.ssh_strict_host_key_checking,
        )
    if opts.os_type == "windows":
        return WinRMTransport(
            opts.credentials,
            scheme="https",
            transport=opts.winrm_transport,  # type: ignore[arg-type]
            server_cert_validation=settings.network.winrm_server_cert_validation,
            connect_timeout=settings.network.connect_timeout_seconds,
            command_timeout=opts.timeout,
        )
    raise ValueError(f"unsupported os_type: {opts.os_type}")


def _new_run_metadata(action: str) -> RunMetadata:
    return RunMetadata(
        run_id=str(uuid.uuid4()),
        action=action,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_scan(
    opts: RunOptions,
    settings: Settings,
    *,
    cache_dir: Optional[Path] = None,
) -> HostReport:
    """Discovery + CVE prioritisation. No remote changes applied."""
    meta = _new_run_metadata("scan")
    started = time.monotonic()
    transport = _make_transport(opts, settings)
    vs = build_vuln_source(settings.vulnerability_source, cache_dir=cache_dir)

    with transport:
        handler = build_handler(opts.os_type, transport)
        disc = discover(handler)
        enriched = prioritize(
            missing=disc.missing,
            installed=disc.installed,
            vuln_source=vs,
            os_type=opts.os_type,
            severity_min=opts.severity_min,
        )

    meta.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    meta.duration_seconds = round(time.monotonic() - started, 2)
    return HostReport(
        metadata=meta,
        target=opts.credentials.safe_dict(),
        os_info=disc.os_info.to_dict(),
        installed_packages_count=len(disc.installed),
        prioritized_patches=[ep.to_dict() for ep in enriched],
        applied_patches=[],
        reboot=None,
    )


def run_patch(
    opts: RunOptions,
    settings: Settings,
    *,
    cache_dir: Optional[Path] = None,
) -> HostReport:
    """Full lifecycle: discover, prioritise, remediate, reboot."""
    meta = _new_run_metadata("patch")
    started = time.monotonic()
    transport = _make_transport(opts, settings)
    vs = build_vuln_source(settings.vulnerability_source, cache_dir=cache_dir)

    applied: list[dict] = []
    reboot_dict: dict | None = None
    os_info_dict: dict = {}
    installed_count = 0
    prioritised: list[dict] = []

    with transport:
        handler = build_handler(opts.os_type, transport)
        disc = discover(handler)
        os_info_dict = disc.os_info.to_dict()
        installed_count = len(disc.installed)

        enriched = prioritize(
            missing=disc.missing,
            installed=disc.installed,
            vuln_source=vs,
            os_type=opts.os_type,
            severity_min=opts.severity_min,
        )
        prioritised = [ep.to_dict() for ep in enriched]

        results = apply_all(
            handler,
            enriched,
            dry_run=opts.dry_run,
            max_attempts=settings.retries.max_attempts,
        )
        applied = [r.to_dict() for r in results]

        # Only attempt reboot if at least one real patch succeeded
        # (or the operator explicitly asked for auto/scheduled even
        # in dry-run, which we still respect via the dry_run flag).
        decision = handle_reboot(
            handler,
            mode=opts.reboot_mode,
            at=opts.reboot_at,
            dry_run=opts.dry_run,
        )
        reboot_dict = decision.to_dict()

    meta.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    meta.duration_seconds = round(time.monotonic() - started, 2)
    return HostReport(
        metadata=meta,
        target=opts.credentials.safe_dict(),
        os_info=os_info_dict,
        installed_packages_count=installed_count,
        prioritized_patches=prioritised,
        applied_patches=applied,
        reboot=reboot_dict,
    )
