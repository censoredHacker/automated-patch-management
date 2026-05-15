"""Pytest fixtures shared across the test suite.

The most important one is :class:`FakeTransport` — a tiny scripted
stand-in for the SSH/WinRM transports that lets us drive the OS
handlers entirely off-line.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

import pytest

from patchmgr.transport.base import CommandResult, Transport


@dataclass
class FakeTransport(Transport):
    """Records executed commands and returns scripted responses.

    Use ``register(prefix, response)`` to set up answers. The first
    registered prefix that matches a command (via ``startswith``) is
    used. Anything unmatched returns ``exit_code=0`` with empty
    stdout/stderr — sufficient for "we don't care about this probe".
    """

    responses: dict[str, CommandResult] = field(default_factory=dict)
    matchers: list[tuple[Callable[[str], bool], CommandResult]] = field(default_factory=list)
    history: list[str] = field(default_factory=list)
    connected: bool = False

    # ------------------------------------------------------------------
    def register(self, prefix: str, *, stdout: str = "", stderr: str = "",
                 exit_code: int = 0) -> None:
        self.responses[prefix] = CommandResult(
            command=prefix, exit_code=exit_code,
            stdout=stdout, stderr=stderr, duration_seconds=0.0,
        )

    def register_match(self, predicate: Callable[[str], bool], *,
                       stdout: str = "", stderr: str = "",
                       exit_code: int = 0) -> None:
        self.matchers.append((predicate, CommandResult(
            command="<match>", exit_code=exit_code,
            stdout=stdout, stderr=stderr, duration_seconds=0.0,
        )))

    # ------------------------------------------------------------------
    def connect(self) -> None:
        self.connected = True

    def exec(self, command: str, *, timeout: int | None = None) -> CommandResult:
        self.history.append(command)
        # Exact / prefix match first.
        for prefix, resp in self.responses.items():
            if command == prefix or command.startswith(prefix):
                return CommandResult(
                    command=command, exit_code=resp.exit_code,
                    stdout=resp.stdout, stderr=resp.stderr,
                    duration_seconds=resp.duration_seconds,
                )
        for pred, resp in self.matchers:
            if pred(command):
                return CommandResult(
                    command=command, exit_code=resp.exit_code,
                    stdout=resp.stdout, stderr=resp.stderr,
                    duration_seconds=resp.duration_seconds,
                )
        return CommandResult(
            command=command, exit_code=0, stdout="", stderr="",
            duration_seconds=0.0,
        )

    def close(self) -> None:
        self.connected = False


@pytest.fixture
def fake_transport() -> FakeTransport:
    return FakeTransport()
