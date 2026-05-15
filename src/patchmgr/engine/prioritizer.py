"""Prioritizer — CVE enrichment + severity filtering.

Two responsibilities:

1. Enrich each :class:`MissingPatch` with CVE data from the configured
   :class:`VulnSource`. The handler-reported severity is kept as a
   floor — if the package manager already says "critical", we trust
   that, even if the NVD lookup returns nothing.
2. Filter out patches below the operator-supplied minimum severity
   and sort the remainder so the highest-impact items are applied
   first (good for MTTR if a long run gets interrupted).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable

from patchmgr.handlers.base import InstalledPackage, MissingPatch
from patchmgr.vulnsource.base import (
    Severity,
    Vulnerability,
    VulnSource,
    VulnSourceError,
    severity_at_least,
    severity_from_cvss,
)


logger = logging.getLogger(__name__)


_SEVERITY_RANK: dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "unknown": 0,
}


@dataclass
class EnrichedPatch:
    patch: MissingPatch
    cves: list[Vulnerability] = field(default_factory=list)

    @property
    def effective_severity(self) -> str:
        """Highest severity across the patch and its associated CVEs."""
        ranks = [_SEVERITY_RANK.get(self.patch.severity, 0)]
        ranks.extend(_SEVERITY_RANK.get(c.severity, 0) for c in self.cves)
        worst = max(ranks)
        for name, rank in sorted(_SEVERITY_RANK.items(), key=lambda kv: -kv[1]):
            if rank == worst:
                return name
        return "unknown"

    def to_dict(self) -> dict[str, object]:
        return {
            "patch": self.patch.to_dict(),
            "cves": [c.to_dict() for c in self.cves],
            "effective_severity": self.effective_severity,
        }


def prioritize(
    *,
    missing: Iterable[MissingPatch],
    installed: Iterable[InstalledPackage],
    vuln_source: VulnSource | None,
    os_type: str,
    severity_min: Severity = "high",
) -> list[EnrichedPatch]:
    """Return a list of :class:`EnrichedPatch` ordered by severity desc."""
    installed_index = {p.name.lower(): p for p in installed}
    enriched: list[EnrichedPatch] = []

    for patch in missing:
        cves: list[Vulnerability] = []
        if vuln_source and patch.package:
            ip = installed_index.get(patch.package.lower())
            version = (
                patch.current_version
                or (ip.version if ip else "")
                or "unknown"
            )
            try:
                cves = list(
                    vuln_source.lookup(patch.package, version, os_type=os_type)
                )
            except VulnSourceError as e:
                logger.warning("CVE lookup failed for %s: %s", patch.package, e)
        enriched.append(EnrichedPatch(patch=patch, cves=cves))

    # Filter by minimum severity.
    filtered = [
        ep for ep in enriched
        if severity_at_least(  # type: ignore[arg-type]
            _normalize_severity(ep.effective_severity), severity_min
        )
    ]

    filtered.sort(
        key=lambda ep: _SEVERITY_RANK.get(ep.effective_severity, 0),
        reverse=True,
    )
    logger.info(
        "prioritised %d/%d patches at severity>=%s",
        len(filtered), len(enriched), severity_min,
    )
    return filtered


def _normalize_severity(value: str) -> Severity:
    """Coerce arbitrary severity strings into the canonical 5-bucket set."""
    v = value.lower()
    if v in ("critical", "high", "medium", "low", "none"):
        return v  # type: ignore[return-value]
    if v == "unknown":
        return "low"  # be conservative
    try:
        return severity_from_cvss(float(v))
    except ValueError:
        return "low"
