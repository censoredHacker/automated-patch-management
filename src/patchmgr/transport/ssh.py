"""SSH transport built on top of paramiko.

Used for both Linux and AIX targets. Highlights:

* Honours an optional ``known_hosts`` file and **rejects** unknown
  hosts by default (configurable via ``strict_host_key_checking``).
* Supports password OR private key (with optional passphrase) auth.
* Enforces a connect timeout and a per-command timeout — a hung remote
  shell will *not* hang the whole tool.
"""

from __future__ import annotations

import logging
import socket
import time
from pathlib import Path
from typing import Optional

import paramiko

from patchmgr.credentials import Credentials
from patchmgr.transport.base import (
    CommandResult,
    CommandTimeout,
    ConnectionError,
    Transport,
    TransportError,
)


logger = logging.getLogger(__name__)


class SSHTransport(Transport):
    """Paramiko-backed SSH transport."""

    def __init__(
        self,
        credentials: Credentials,
        *,
        connect_timeout: int = 30,
        command_timeout: int = 600,
        strict_host_key_checking: bool = True,
        known_hosts: Optional[Path] = None,
    ) -> None:
        self._creds = credentials
        self._connect_timeout = connect_timeout
        self._command_timeout = command_timeout
        self._strict = strict_host_key_checking
        self._known_hosts = known_hosts
        self._client: Optional[paramiko.SSHClient] = None

    # ------------------------------------------------------------------
    def connect(self) -> None:
        if self._client is not None:
            return  # idempotent

        client = paramiko.SSHClient()
        if self._known_hosts and self._known_hosts.exists():
            client.load_host_keys(str(self._known_hosts))
        else:
            client.load_system_host_keys()

        if self._strict:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            # Operators sometimes need this for fresh hosts in a lab.
            # We log loudly because it weakens MITM protection.
            logger.warning(
                "SSH strict host key checking DISABLED for %s — vulnerable to MITM",
                self._creds.host,
            )
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict[str, object] = {
            "hostname": self._creds.host,
            "port": self._creds.port,
            "username": self._creds.username,
            "timeout": self._connect_timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }

        if self._creds.key_path:
            try:
                pkey = self._load_pkey(self._creds.key_path, self._creds.key_passphrase)
            except paramiko.SSHException as e:
                raise ConnectionError(f"failed to load SSH key: {e}") from e
            connect_kwargs["pkey"] = pkey
        else:
            connect_kwargs["password"] = self._creds.password

        try:
            logger.info("connecting via SSH to %s", self._creds)
            client.connect(**connect_kwargs)
        except (paramiko.AuthenticationException, paramiko.BadHostKeyException) as e:
            client.close()
            raise ConnectionError(f"SSH auth failed for {self._creds}: {e}") from e
        except (paramiko.SSHException, socket.error, OSError) as e:
            client.close()
            raise ConnectionError(f"SSH connect failed for {self._creds}: {e}") from e

        self._client = client

    # ------------------------------------------------------------------
    @staticmethod
    def _load_pkey(path: str, passphrase: Optional[str]) -> paramiko.PKey:
        """Try common key formats in order until one succeeds."""
        last_exc: Exception | None = None
        for loader in (
            paramiko.Ed25519Key.from_private_key_file,
            paramiko.ECDSAKey.from_private_key_file,
            paramiko.RSAKey.from_private_key_file,
            paramiko.DSSKey.from_private_key_file,
        ):
            try:
                return loader(path, password=passphrase)  # type: ignore[arg-type]
            except paramiko.SSHException as e:
                last_exc = e
        raise paramiko.SSHException(
            f"could not load key {path!r}: {last_exc}"
        )

    # ------------------------------------------------------------------
    def exec(self, command: str, *, timeout: Optional[int] = None) -> CommandResult:
        if self._client is None:
            raise TransportError("SSH transport is not connected")

        budget = timeout if timeout is not None else self._command_timeout
        logger.debug("SSH exec on %s: %s", self._creds.host, command)
        start = time.monotonic()
        try:
            stdin, stdout, stderr = self._client.exec_command(
                command, timeout=budget, get_pty=False
            )
            stdin.close()
            # Reading exit status drains the channel — must happen *before*
            # we try to read stdout/stderr to avoid deadlocks on big output.
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
        except socket.timeout as e:
            raise CommandTimeout(
                f"command timed out after {budget}s: {command!r}"
            ) from e
        except paramiko.SSHException as e:
            raise TransportError(f"SSH exec failed: {e}") from e
        duration = time.monotonic() - start
        return CommandResult(
            command=command,
            exit_code=exit_code,
            stdout=out,
            stderr=err,
            duration_seconds=duration,
        )

    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            finally:
                self._client = None
