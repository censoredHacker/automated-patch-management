"""Pluggable vulnerability intelligence sources.

A *VulnSource* answers one question: given a package name + version +
operating system, what known CVEs apply and what is their severity?

We ship two implementations out of the box:

* :class:`patchmgr.vulnsource.nvd.NVDSource` — calls the public NVD 2.0
  REST API, with a 24-hour on-disk cache and exponential-backoff retry.
* :class:`patchmgr.vulnsource.local_json.LocalJSONSource` — reads a
  static JSON file. Useful for air-gapped environments and tests.

The factory :func:`build_vuln_source` picks an implementation based on
the :class:`Settings`.
"""

from patchmgr.vulnsource.base import (
    Severity,
    Vulnerability,
    VulnSource,
    VulnSourceError,
)
from patchmgr.vulnsource.factory import build_vuln_source

__all__ = (
    "Severity",
    "Vulnerability",
    "VulnSource",
    "VulnSourceError",
    "build_vuln_source",
)
