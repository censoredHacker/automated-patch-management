"""Prioritizer logic tests (no network)."""

from __future__ import annotations

from patchmgr.engine.prioritizer import prioritize
from patchmgr.handlers.base import InstalledPackage, MissingPatch
from patchmgr.vulnsource.base import Vulnerability, VulnSource


class _StubSource(VulnSource):
    def __init__(self, mapping: dict[str, list[Vulnerability]]):
        self._mapping = mapping

    def lookup(self, package, version, *, os_type):
        return self._mapping.get(package, [])


def _vuln(cve, sev, score, pkg) -> Vulnerability:
    return Vulnerability(
        cve_id=cve, package=pkg, installed_version="x", fixed_version=None,
        cvss_score=score, severity=sev,
    )


def test_filter_below_threshold():
    missing = [
        MissingPatch(identifier="foo", package="foo", severity="medium"),
        MissingPatch(identifier="bar", package="bar", severity="critical"),
    ]
    out = prioritize(
        missing=missing, installed=[],
        vuln_source=None, os_type="linux",
        severity_min="high",
    )
    assert [ep.patch.identifier for ep in out] == ["bar"]


def test_cve_lookup_raises_severity():
    missing = [MissingPatch(identifier="foo", package="foo", severity="low")]
    src = _StubSource({"foo": [_vuln("CVE-1", "critical", 9.8, "foo")]})
    out = prioritize(
        missing=missing,
        installed=[InstalledPackage(name="foo", version="1.0")],
        vuln_source=src, os_type="linux", severity_min="high",
    )
    assert len(out) == 1
    assert out[0].effective_severity == "critical"


def test_sort_order_critical_first():
    missing = [
        MissingPatch(identifier="med", package="m", severity="medium"),
        MissingPatch(identifier="crit", package="c", severity="critical"),
        MissingPatch(identifier="high", package="h", severity="high"),
    ]
    out = prioritize(
        missing=missing, installed=[], vuln_source=None,
        os_type="linux", severity_min="medium",
    )
    assert [ep.patch.identifier for ep in out] == ["crit", "high", "med"]
