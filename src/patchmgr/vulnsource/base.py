"""Vulnerability source ABC and shared data classes.

The CVSS-to-severity mapping follows NVD conventions:

    9.0 - 10.0  -> critical
    7.0 -  8.9  -> high
    4.0 -  6.9  -> medium
    0.1 -  3.9  -> low
    0.0         -> none

We intentionally keep the data model small so that handlers from
different OS families can produce comparable records.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Iterable, Literal, Optional


Severity = Literal["none", "low", "medium", "high", "critical"]

_SEVERITY_ORDER: dict[Severity, int] = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_from_cvss(score: float) -> Severity:
    """Convert a CVSS base score to a textual severity bucket."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def severity_at_least(value: Severity, minimum: Severity) -> bool:
    """True if *value* is at least as severe as *minimum*."""
    return _SEVERITY_ORDER[value] >= _SEVERITY_ORDER[minimum]


class VulnSourceError(Exception):
    """Raised when a vulnerability source cannot return data."""


@dataclass(frozen=True)
class Vulnerability:
    """One known vulnerability affecting a specific package version."""

    cve_id: str
    package: str
    installed_version: str
    fixed_version: Optional[str]
    cvss_score: float
    severity: Severity
    summary: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "cve_id": self.cve_id,
            "package": self.package,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "summary": self.summary,
            "references": list(self.references),
        }


class VulnSource(abc.ABC):
    """ABC for vulnerability intelligence providers."""

    @abc.abstractmethod
    def lookup(
        self,
        package: str,
        version: str,
        *,
        os_type: str,
    ) -> Iterable[Vulnerability]:
        """Return all known vulnerabilities for *package* at *version*."""
