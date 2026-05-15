"""Verify the logging filter scrubs secrets."""

from __future__ import annotations

import logging

from patchmgr.logging_setup import RedactingFilter


def _emit(record_msg: str, args=()) -> str:
    flt = RedactingFilter()
    record = logging.LogRecord(
        name="t", level=logging.INFO, pathname=__file__, lineno=1,
        msg=record_msg, args=args, exc_info=None,
    )
    flt.filter(record)
    return record.getMessage()


def test_redacts_ip_user_pass():
    out = _emit("connecting to 10.0.0.1:admin:hunter2 now")
    assert "hunter2" not in out
    assert "REDACTED" in out


def test_redacts_password_kv():
    out = _emit("payload password=hunter2 trailing")
    assert "hunter2" not in out


def test_redacts_token():
    out = _emit("Authorization: Bearer abc.def.ghi")
    assert "abc.def.ghi" not in out


def test_does_not_touch_innocent_strings():
    out = _emit("nothing secret here, just stats=42")
    assert out == "nothing secret here, just stats=42"
