"""Safe shell-quoting helpers shared by the OS handlers.

We deliberately avoid building remote command strings by `f"...{var}..."`
because that is the canonical command-injection footgun. Every handler
that builds a shell command must route untrusted values through
:func:`sh_quote` (POSIX) or :func:`ps_quote` (PowerShell).
"""

from __future__ import annotations

import shlex


def sh_quote(value: str) -> str:
    """Quote *value* for safe inclusion in a POSIX shell command."""
    return shlex.quote(value)


def ps_quote(value: str) -> str:
    """Quote *value* for inclusion in a PowerShell single-quoted string.

    PowerShell single-quoted strings only need ``'`` to be doubled.
    """
    return "'" + value.replace("'", "''") + "'"
