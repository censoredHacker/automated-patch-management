"""Static JSON-file vulnerability source.

Use cases:

* air-gapped environments where the NVD API is unreachable;
* deterministic unit / integration tests;
* feeding internal vulnerability data (Tenable, Qualys exports, etc.)
  by first converting it to this simple shape.

File schema (JSON):

```json
{
  "openssh-server": [
    {
      "cve_id": "CVE-2024-0001",
      "affected_versions": ["<8.9p1"],
      "fixed_version": "8.9p1",
      "cvss_score": 7.5,
      "summary": "Example issue",
      "references": ["https://example/CVE-2024-0001"]
    }
  ]
}
```

The version matcher is intentionally simple — it understands
``<x.y``, ``<=x.y``, ``==x.y`` and an exact string match. Anything
more complex should be done in the source-of-truth tool and exported
as discrete versions.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Iterable, Optional

from patchmgr.vulnsource.base import (
    Vulnerability,
    VulnSource,
    VulnSourceError,
    severity_from_cvss,
)


logger = logging.getLogger(__name__)


_OP_RE = re.compile(r"^\s*(<=|<|==|=|>=|>)?\s*(.+?)\s*$")


def _version_tuple(v: str) -> tuple[int, ...]:
    """Convert ``1.2.3p4`` to a comparable tuple ``(1, 2, 3, 4)``.

    Non-numeric segments are coerced to ``0`` after splitting on
    common separators — good enough for the simple, hand-curated data
    this source is intended to hold.
    """
    parts = re.split(r"[.\-_p]", v)
    out: list[int] = []
    for p in parts:
        digits = re.match(r"\d+", p)
        out.append(int(digits.group(0)) if digits else 0)
    return tuple(out)


def _matches(spec: str, installed: str) -> bool:
    """True if *installed* satisfies the version constraint *spec*."""
    m = _OP_RE.match(spec)
    if not m:
        return False
    op, target = m.group(1) or "==", m.group(2)
    a, b = _version_tuple(installed), _version_tuple(target)
    if op in ("==", "="):
        return a == b or installed == target
    if op == "<":
        return a < b
    if op == "<=":
        return a <= b
    if op == ">":
        return a > b
    if op == ">=":
        return a >= b
    return False


class LocalJSONSource(VulnSource):
    """Read vulnerabilities from a JSON file."""

    def __init__(self, path: Path) -> None:
        if not path.exists():
            raise VulnSourceError(f"local vuln file not found: {path}")
        try:
            self._data: dict[str, list[dict]] = json.loads(
                path.read_text(encoding="utf-8")
            )
        except json.JSONDecodeError as e:
            raise VulnSourceError(f"invalid JSON in {path}: {e}") from e
        logger.info("loaded %d packages from local vuln file %s",
                    len(self._data), path)

    def lookup(
        self,
        package: str,
        version: str,
        *,
        os_type: str,
    ) -> Iterable[Vulnerability]:
        entries = self._data.get(package, [])
        out: list[Vulnerability] = []
        for entry in entries:
            specs = entry.get("affected_versions", [])
            if not any(_matches(s, version) for s in specs):
                continue
            score = float(entry.get("cvss_score", 0.0))
            fixed: Optional[str] = entry.get("fixed_version")
            out.append(
                Vulnerability(
                    cve_id=entry.get("cve_id", "UNKNOWN"),
                    package=package,
                    installed_version=version,
                    fixed_version=fixed,
                    cvss_score=score,
                    severity=severity_from_cvss(score),
                    summary=entry.get("summary", ""),
                    references=tuple(entry.get("references", [])),
                )
            )
        return out
