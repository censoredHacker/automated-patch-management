"""Reboot strategy.

Three modes are supported:

* ``auto``      — reboot immediately if the host says it needs it.
* ``scheduled`` — schedule a reboot for a specific HH:MM (UTC on host).
* ``manual``    — only record the requirement, never actually reboot.

The HH:MM scheduler computes a delay in minutes and hands that to the
handler. We deliberately keep the maths in Python (rather than
relying on the OS scheduler) because Windows ``shutdown.exe`` and
Linux ``shutdown`` already accept a delay parameter.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from patchmgr.handlers.base import OSHandler


logger = logging.getLogger(__name__)


RebootMode = Literal["auto", "scheduled", "manual"]

_HHMM_RE = re.compile(r"^(?P<h>[0-2]?\d):(?P<m>[0-5]\d)$")


@dataclass
class RebootDecision:
    required: bool
    mode: RebootMode
    scheduled_at: str | None = None
    issued: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "required": self.required,
            "mode": self.mode,
            "scheduled_at": self.scheduled_at,
            "issued": self.issued,
            "note": self.note,
        }


def _parse_hhmm_delay(at: str, *, now: datetime | None = None) -> int:
    """Return how many minutes from *now* until the next ``HH:MM``."""
    m = _HHMM_RE.match(at.strip())
    if not m:
        raise ValueError(f"--at must be HH:MM, got {at!r}")
    h, mi = int(m.group("h")), int(m.group("m"))
    if not (0 <= h < 24):
        raise ValueError(f"hour out of range: {h}")
    base = now or datetime.now()
    target = base.replace(hour=h, minute=mi, second=0, microsecond=0)
    if target <= base:
        target += timedelta(days=1)
    return int((target - base).total_seconds() // 60)


def handle_reboot(
    handler: OSHandler,
    *,
    mode: RebootMode,
    at: str | None = None,
    dry_run: bool = False,
) -> RebootDecision:
    """Apply the configured reboot policy and return the decision."""
    required = handler.reboot_required()
    decision = RebootDecision(required=required, mode=mode)

    if not required:
        decision.note = "host reports no reboot required"
        return decision

    if dry_run:
        decision.note = "dry-run: reboot not issued"
        return decision

    if mode == "manual":
        decision.note = "reboot required — manual approval mode, not issuing"
        return decision

    if mode == "auto":
        handler.reboot(delay_minutes=0)
        decision.issued = True
        decision.note = "auto-reboot issued"
        return decision

    if mode == "scheduled":
        if not at:
            raise ValueError("scheduled reboot requires --at HH:MM")
        delay = _parse_hhmm_delay(at)
        handler.reboot(delay_minutes=delay)
        decision.issued = True
        decision.scheduled_at = at
        decision.note = f"reboot scheduled in {delay} minutes (at {at})"
        return decision

    raise ValueError(f"unknown reboot mode: {mode}")
