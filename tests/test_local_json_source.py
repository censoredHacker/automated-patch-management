"""LocalJSONSource version-matching tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from patchmgr.vulnsource.local_json import LocalJSONSource


@pytest.fixture
def vuln_file(tmp_path: Path) -> Path:
    data = {
        "openssh-server": [
            {
                "cve_id": "CVE-2024-0001",
                "affected_versions": ["<8.9p2"],
                "fixed_version": "8.9p2",
                "cvss_score": 7.5,
                "summary": "test issue",
                "references": ["https://example/CVE-2024-0001"],
            },
            {
                "cve_id": "CVE-2024-0002",
                "affected_versions": ["==8.9p1"],
                "fixed_version": "8.9p2",
                "cvss_score": 9.1,
            },
        ],
    }
    p = tmp_path / "vulns.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_match_below_fixed_version(vuln_file: Path):
    src = LocalJSONSource(vuln_file)
    out = list(src.lookup("openssh-server", "8.9p1", os_type="linux"))
    cves = {v.cve_id for v in out}
    assert cves == {"CVE-2024-0001", "CVE-2024-0002"}
    crit = next(v for v in out if v.cve_id == "CVE-2024-0002")
    assert crit.severity == "critical"


def test_no_match_when_already_patched(vuln_file: Path):
    src = LocalJSONSource(vuln_file)
    out = list(src.lookup("openssh-server", "9.0", os_type="linux"))
    assert out == []


def test_unknown_package_returns_empty(vuln_file: Path):
    src = LocalJSONSource(vuln_file)
    assert list(src.lookup("does-not-exist", "1.0", os_type="linux")) == []
