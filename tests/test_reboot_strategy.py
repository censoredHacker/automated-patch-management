"""Reboot strategy unit tests."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

import pytest

from patchmgr.engine.reboot import _parse_hhmm_delay, handle_reboot
from patchmgr.handlers.base import (
    InstalledPackage, MissingPatch, OSHandler, OSInfo, PatchResult,
)


class _StubHandler(OSHandler):
    os_type = "linux"

    def __init__(self, *, requires_reboot: bool):
        super().__init__(transport=None)
        self._requires = requires_reboot
        self.issued: tuple[int, ...] | None = None

    def detect(self) -> OSInfo:
        return OSInfo(os_type="linux", distro="x", version="1")

    def list_packages(self) -> Iterable[InstalledPackage]:
        return []

    def list_missing_patches(self) -> Iterable[MissingPatch]:
        return []

    def apply_patch(self, patch, *, dry_run):
        return PatchResult(patch=patch, success=True)

    def reboot_required(self) -> bool:
        return self._requires

    def reboot(self, *, delay_minutes: int = 0) -> None:
        self.issued = (delay_minutes,)


def test_parse_hhmm_today_in_future():
    now = datetime(2025, 1, 1, 1, 0)
    assert _parse_hhmm_delay("02:30", now=now) == 90


def test_parse_hhmm_rolls_to_tomorrow():
    now = datetime(2025, 1, 1, 23, 0)
    # 01:00 next day = 120 minutes ahead.
    assert _parse_hhmm_delay("01:00", now=now) == 120


def test_parse_hhmm_invalid():
    with pytest.raises(ValueError):
        _parse_hhmm_delay("25:00")


def test_no_reboot_when_not_required():
    h = _StubHandler(requires_reboot=False)
    decision = handle_reboot(h, mode="auto")
    assert decision.required is False
    assert decision.issued is False
    assert h.issued is None


def test_manual_mode_does_not_issue():
    h = _StubHandler(requires_reboot=True)
    decision = handle_reboot(h, mode="manual")
    assert decision.required is True
    assert decision.issued is False
    assert h.issued is None


def test_auto_mode_issues_immediately():
    h = _StubHandler(requires_reboot=True)
    decision = handle_reboot(h, mode="auto")
    assert decision.issued is True
    assert h.issued == (0,)


def test_dry_run_never_issues():
    h = _StubHandler(requires_reboot=True)
    decision = handle_reboot(h, mode="auto", dry_run=True)
    assert decision.issued is False
    assert h.issued is None
