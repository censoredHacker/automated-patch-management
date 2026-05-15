"""Transport abstract base class.

A *transport* is the minimal channel needed to operate on a remote
host: open a session, run a command, read stdout/stderr/exit code,
close cleanly. Anything richer (file upload, interactive shell,
etc.) is added by subclasses only when a handler actually needs it.

This abstraction lets us:

* unit-test handlers without any real network I/O (a fake transport
  is trivial);
* swap SSH for WinRM at runtime based on the target OS;
* later add new transports (e.g. AWS SSM, Azure Run Command) without
  touching handler code.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Optional


class TransportError(Exception):
    """Base class for all transport-related failures."""


class ConnectionError(TransportError):  # noqa: A001 - we want this name
    """Raised when the underlying transport cannot connect or auth fails."""


class CommandTimeout(TransportError):
    """Raised when a remote command exceeds its allotted time budget."""


@dataclass(frozen=True)
class CommandResult:
    """Result of a single remote command.

    ``exit_code`` of ``-1`` is reserved for "we never got an exit code"
    situations (timeouts, channel closed unexpectedly, ...) so callers
    can distinguish those from a genuine non-zero exit.
    """

    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def raise_for_status(self) -> None:
        """Raise :class:`TransportError` if the command did not succeed."""
        if not self.ok:
            raise TransportError(
                f"command failed (exit={self.exit_code}): "
                f"{self.command!r}\nstderr: {self.stderr.strip()[:500]}"
            )


class Transport(abc.ABC):
    """Abstract remote command channel.

    Subclasses MUST be safe to use as a context manager so that
    connections are torn down even when an exception is raised mid-run.
    """

    @abc.abstractmethod
    def connect(self) -> None:
        """Establish the underlying network connection."""

    @abc.abstractmethod
    def exec(self, command: str, *, timeout: Optional[int] = None) -> CommandResult:
        """Run *command* on the remote host and return the result.

        Implementations must not raise on a non-zero exit code; that is
        the caller's job via :meth:`CommandResult.raise_for_status`.
        They MUST raise :class:`TransportError` (or a subclass) for
        anything that prevents producing a real result.
        """

    @abc.abstractmethod
    def close(self) -> None:
        """Tear down the connection. Safe to call multiple times."""

    # ------------------------------------------------------------------
    # Context-manager sugar so callers can write `with transport: ...`.
    # ------------------------------------------------------------------
    def __enter__(self) -> "Transport":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: D401
        self.close()
