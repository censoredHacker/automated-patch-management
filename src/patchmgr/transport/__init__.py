"""Connection abstractions for remote hosts.

The :class:`patchmgr.transport.base.Transport` ABC defines a tiny
contract — connect, execute, close — that the rest of the codebase
talks to. Concrete implementations live in:

* :mod:`patchmgr.transport.ssh`   — SSH for Linux and AIX
* :mod:`patchmgr.transport.winrm` — WinRM-over-HTTPS for Windows

Keeping the surface this small means handlers do not need to know
which OS they are running against at the connection level.
"""

from patchmgr.transport.base import (
    CommandResult,
    Transport,
    TransportError,
    ConnectionError as TransportConnectionError,
)

__all__ = (
    "CommandResult",
    "Transport",
    "TransportError",
    "TransportConnectionError",
)
