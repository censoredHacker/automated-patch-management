"""WinRM (Windows Remote Management) transport.

This wraps the `pywinrm` library to give Windows hosts the same simple
``connect / exec / close`` surface as SSH. Two things to keep in mind:

* We **default to HTTPS on port 5986** and validate the server cert.
  Plaintext HTTP / disabled cert validation are possible but the
  caller has to opt in explicitly — there is no silent downgrade.
* PowerShell stderr is split into multiple "streams" by WinRM. We
  flatten them into a single stderr string so the rest of the code
  does not have to care.
"""

from __future__ import annotations

import logging
import time
from typing import Literal, Optional

try:
    import winrm
    from winrm.exceptions import (
        InvalidCredentialsError,
        WinRMTransportError,
        WinRMOperationTimeoutError,
    )
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "pywinrm is required for the WinRM transport. "
        "Install with `pip install pywinrm`."
    ) from e

from patchmgr.credentials import Credentials
from patchmgr.transport.base import (
    CommandResult,
    CommandTimeout,
    ConnectionError,
    Transport,
    TransportError,
)


logger = logging.getLogger(__name__)


WinRMTransportName = Literal["ntlm", "kerberos", "basic", "credssp"]


class WinRMTransport(Transport):
    """`pywinrm`-backed transport for Windows targets."""

    def __init__(
        self,
        credentials: Credentials,
        *,
        scheme: Literal["https", "http"] = "https",
        port: Optional[int] = None,
        transport: WinRMTransportName = "ntlm",
        server_cert_validation: Literal["validate", "ignore"] = "validate",
        connect_timeout: int = 30,
        command_timeout: int = 600,
    ) -> None:
        self._creds = credentials
        self._scheme = scheme
        self._port = port or (5986 if scheme == "https" else 5985)
        self._transport = transport
        self._server_cert_validation = server_cert_validation
        self._connect_timeout = connect_timeout
        self._command_timeout = command_timeout
        self._session: Optional[winrm.Session] = None

        if scheme == "http":
            logger.warning(
                "WinRM transport using plaintext HTTP for %s — credentials "
                "and command output are sent unencrypted.",
                credentials.host,
            )

    # ------------------------------------------------------------------
    def connect(self) -> None:
        if self._session is not None:
            return
        endpoint = f"{self._scheme}://{self._creds.host}:{self._port}/wsman"
        try:
            self._session = winrm.Session(
                target=endpoint,
                auth=(self._creds.username, self._creds.password or ""),
                transport=self._transport,
                server_cert_validation=self._server_cert_validation,
                read_timeout_sec=self._command_timeout + 10,
                operation_timeout_sec=self._command_timeout,
            )
            # pywinrm is lazy — force an actual probe so connect errors
            # surface here rather than on the first exec call.
            logger.info("probing WinRM endpoint %s", endpoint)
            probe = self._session.run_ps("$PSVersionTable.PSVersion.ToString()")
            if probe.status_code != 0:
                raise ConnectionError(
                    f"WinRM probe failed: {probe.std_err!r}"
                )
        except InvalidCredentialsError as e:
            raise ConnectionError(f"WinRM auth failed for {self._creds}: {e}") from e
        except WinRMTransportError as e:
            raise ConnectionError(f"WinRM transport error to {self._creds}: {e}") from e
        except Exception as e:  # pragma: no cover - defensive
            raise ConnectionError(f"WinRM connect failed: {e}") from e

    # ------------------------------------------------------------------
    def exec(self, command: str, *, timeout: Optional[int] = None) -> CommandResult:
        """Execute *command* as a PowerShell script on the remote host.

        We always go through PowerShell rather than ``cmd.exe`` because
        the downstream handlers rely on PowerShell modules
        (``PSWindowsUpdate``, ``Get-HotFix``).
        """
        if self._session is None:
            raise TransportError("WinRM transport is not connected")
        # pywinrm uses session-level timeout; per-call override would
        # require rebuilding the session, which is expensive. We accept
        # the parameter for API parity and log a debug note if it
        # differs from the configured value.
        if timeout is not None and timeout != self._command_timeout:
            logger.debug(
                "per-call timeout %ss ignored; session timeout is %ss",
                timeout,
                self._command_timeout,
            )

        logger.debug("WinRM exec on %s: %s", self._creds.host, command)
        start = time.monotonic()
        try:
            result = self._session.run_ps(command)
        except WinRMOperationTimeoutError as e:
            raise CommandTimeout(
                f"WinRM command timed out: {command!r}"
            ) from e
        except WinRMTransportError as e:
            raise TransportError(f"WinRM exec failed: {e}") from e
        duration = time.monotonic() - start

        return CommandResult(
            command=command,
            exit_code=result.status_code,
            stdout=result.std_out.decode("utf-8", errors="replace") if result.std_out else "",
            stderr=result.std_err.decode("utf-8", errors="replace") if result.std_err else "",
            duration_seconds=duration,
        )

    # ------------------------------------------------------------------
    def close(self) -> None:
        # pywinrm does not keep a persistent connection, so there is
        # nothing to tear down. We just drop the session reference.
        self._session = None
