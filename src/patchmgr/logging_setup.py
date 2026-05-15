"""Centralised logging configuration for patchmgr.

Two handlers are configured:

* a **console handler** with a short human-readable format so operators
  can follow progress in real time;
* a **file handler** that writes structured JSON (one record per line)
  so logs can be ingested by Splunk / ELK / Loki without parsing rules.

A `RedactingFilter` is attached to every handler so that anything that
looks like a password or secret is masked before it is written
anywhere. This is defence in depth — the rest of the code already tries
not to log secrets, but mistakes happen, and a credential in a log file
is a serious incident.
"""

from __future__ import annotations

import logging
import logging.handlers
import re
from pathlib import Path
from typing import Iterable

try:
    # python-json-logger is a small dependency that turns LogRecords into
    # JSON. We import lazily so that `import patchmgr` does not fail in
    # environments where the optional dep is missing.
    from pythonjsonlogger import jsonlogger
except ImportError:  # pragma: no cover - dependency missing at runtime
    jsonlogger = None  # type: ignore[assignment]


# Patterns that almost certainly contain a secret. The regex is applied
# to the final formatted log message AND to every string argument.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    # IP:user:password style targets (the password is the 3rd field).
    re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}:[^:\s]+:)([^\s'\"]+)"),
    # key=value style (password=..., token=..., secret=...).
    re.compile(
        r"((?:password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*)"
        r"([^\s'\",}]+)",
        re.IGNORECASE,
    ),
    # Authorization headers.
    re.compile(r"(Authorization:\s*\S+\s+)(\S+)", re.IGNORECASE),
)

_REDACTED = "***REDACTED***"


def _redact(text: str) -> str:
    """Return *text* with any obvious secrets replaced by ``***REDACTED***``."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)}{_REDACTED}", text)
    return text


class RedactingFilter(logging.Filter):
    """Logging filter that scrubs secrets from messages and arguments.

    The filter mutates the LogRecord in place so that *every* handler
    downstream sees the redacted version. It is intentionally cheap
    (just a few regex substitutions per record).
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        # Redact positional args first so %-formatting still works.
        # IMPORTANT: only touch *string* args. Coercing ints/floats to
        # str here would break callers like
        # ``logger.info("found %d patches", count)`` under Python 3.14
        # which strictly enforces ``%d`` against ``int``.
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: (_redact(v) if isinstance(v, str) else v)
                    for k, v in record.args.items()
                }
            else:
                record.args = tuple(
                    _redact(a) if isinstance(a, str) else a
                    for a in record.args
                )
        if isinstance(record.msg, str):
            record.msg = _redact(record.msg)
        return True


def configure_logging(
    *,
    log_file: Path | None = None,
    level: str = "INFO",
    json_file: bool = True,
    console: bool = True,
) -> None:
    """Configure the root logger.

    Parameters
    ----------
    log_file:
        Path to a file that will receive structured JSON logs. Parent
        directories are created automatically. ``None`` disables the
        file handler.
    level:
        Logging level name (``DEBUG``, ``INFO``, ...). Invalid names
        fall back to ``INFO`` so a typo does not silence the tool.
    json_file:
        Write the file handler in JSON format. Set ``False`` to use a
        plain text format (useful when grepping by hand).
    console:
        Whether to also emit human-readable logs to stderr.
    """
    root = logging.getLogger()
    # Wipe any handlers configured by libraries we imported earlier, so
    # repeat calls (e.g. in tests) do not stack up duplicates.
    for h in list(root.handlers):
        root.removeHandler(h)

    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    redactor = RedactingFilter()

    handlers: list[logging.Handler] = []

    if console:
        ch = logging.StreamHandler()
        ch.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        handlers.append(ch)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        if json_file and jsonlogger is not None:
            fh.setFormatter(
                jsonlogger.JsonFormatter(
                    "%(asctime)s %(levelname)s %(name)s %(message)s"
                )
            )
        else:
            fh.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)s %(name)s: %(message)s"
                )
            )
        handlers.append(fh)

    for h in handlers:
        h.addFilter(redactor)
        root.addHandler(h)

    # Quiet down a few chatty third-party loggers.
    for noisy in ("paramiko.transport", "urllib3", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Convenience helper so callers do not import the stdlib themselves."""
    return logging.getLogger(name)


__all__: Iterable[str] = ("configure_logging", "get_logger", "RedactingFilter")
