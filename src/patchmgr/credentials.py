"""Parsing and safe representation of remote-host credentials.

The CLI accepts a target in the format ``IP:username:password``. That
string can contain colons inside the password, so we split from the
left twice and treat everything after the second colon as the
password.

The resulting :class:`Credentials` object overrides ``__repr__`` and
``__str__`` so that printing it never accidentally reveals the
password — only the host and username are shown.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional


# Hostname regex per RFC 1123 (labels up to 63 chars, total up to 253).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class CredentialParseError(ValueError):
    """Raised when an IP:user:pass string cannot be parsed."""


@dataclass(frozen=True)
class Credentials:
    """Immutable bundle of remote-host connection details.

    Either ``password`` or ``key_path`` must be set. ``port`` defaults
    to 22 for SSH callers and is ignored by the WinRM transport which
    uses its own default.
    """

    host: str
    username: str
    password: Optional[str] = field(default=None, repr=False)
    key_path: Optional[str] = None
    key_passphrase: Optional[str] = field(default=None, repr=False)
    port: int = 22

    def __post_init__(self) -> None:  # noqa: D401
        if not self.host:
            raise CredentialParseError("host is required")
        if not self.username:
            raise CredentialParseError("username is required")
        if not self.password and not self.key_path:
            raise CredentialParseError(
                "either a password or an SSH key path must be supplied"
            )

    # ------------------------------------------------------------------
    # Safe string representations — never leak the password.
    # ------------------------------------------------------------------
    def __str__(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"

    def safe_dict(self) -> dict[str, str | int | None]:
        """Return a dict suitable for logging / reports (no secrets)."""
        return {
            "host": self.host,
            "username": self.username,
            "port": self.port,
            "auth": "key" if self.key_path else "password",
        }


def _is_valid_host(value: str) -> bool:
    """True if *value* is a syntactically valid IPv4/IPv6 address or hostname."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(value))


def parse_target(
    raw: str,
    *,
    default_port: int = 22,
    key_path: str | None = None,
    key_passphrase: str | None = None,
) -> Credentials:
    """Parse an ``IP:user:password`` (or ``IP:port:user:password``) string.

    Examples
    --------
    >>> parse_target("10.0.0.1:admin:hunter2").host
    '10.0.0.1'
    >>> parse_target("10.0.0.1:2222:admin:hunter2").port
    2222

    A password that itself contains ``:`` is preserved verbatim because
    we split from the right after locating the first two fields.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise CredentialParseError("target string is empty")

    parts = raw.split(":", 3)
    if len(parts) < 3:
        raise CredentialParseError(
            "target must be in the format IP:username:password "
            "or IP:port:username:password"
        )

    if len(parts) == 4 and parts[1].isdigit():
        host, port_s, username, password = parts
        port = int(port_s)
    else:
        # 3 parts, or 4 parts where the second field is part of the password.
        # Re-split as host : username : <rest-as-password>.
        host, username, password = raw.split(":", 2)
        port = default_port

    if not _is_valid_host(host):
        raise CredentialParseError(f"invalid host or IP address: {host!r}")
    if not username:
        raise CredentialParseError("username is empty")
    if not password and not key_path:
        raise CredentialParseError("password is empty and no key supplied")
    if not (1 <= port <= 65535):
        raise CredentialParseError(f"port out of range: {port}")

    return Credentials(
        host=host,
        username=username,
        password=password or None,
        key_path=key_path,
        key_passphrase=key_passphrase,
        port=port,
    )


__all__ = ("Credentials", "CredentialParseError", "parse_target")
