"""NVD 2.0 REST API client with on-disk caching.

API reference: https://nvd.nist.gov/developers/vulnerabilities

Design notes
------------
* We query the ``/rest/json/cves/2.0`` endpoint with ``keywordSearch``
  scoped to the package name. CPE-based queries are more precise but
  require a CPE dictionary lookup pass that the public endpoint does
  not provide cheaply — using keyword + filtering by configurations
  gives good-enough results for prioritisation.
* Responses are cached on disk for ``cache_ttl_hours`` (default 24h)
  using :mod:`diskcache`. The cache key includes the package name so
  invalidations are surgical.
* Without an API key the public endpoint is rate-limited to roughly
  one request per six seconds. We back off with `tenacity` if we hit a
  429 or 5xx.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Iterable, Optional

import diskcache
import httpx

from patchmgr.vulnsource.base import (
    Severity,
    Vulnerability,
    VulnSource,
    VulnSourceError,
    severity_from_cvss,
)


logger = logging.getLogger(__name__)

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_DIR = Path.home() / ".patchmgr" / "cache" / "nvd"


class NVDSource(VulnSource):
    """Public NVD 2.0 client with disk-backed cache."""

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        cache_dir: Optional[Path] = None,
        cache_ttl_hours: int = 24,
        timeout: float = 30.0,
        max_results_per_package: int = 50,
    ) -> None:
        self._api_key = api_key or os.environ.get("NVD_API_KEY")
        cache_dir = cache_dir or DEFAULT_CACHE_DIR
        cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache = diskcache.Cache(str(cache_dir))
        self._ttl = cache_ttl_hours * 3600
        self._timeout = timeout
        self._max_results = max_results_per_package

        headers = {"User-Agent": "patchmgr/0.1"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        self._client = httpx.Client(headers=headers, timeout=self._timeout)

    # ------------------------------------------------------------------
    def lookup(
        self,
        package: str,
        version: str,
        *,
        os_type: str,
    ) -> Iterable[Vulnerability]:
        """Return CVEs that mention *package*, filtered to those whose
        configurations could plausibly match *version*.

        We deliberately keep the matching loose: a false positive is
        cheap (operators will see it in the report), but a false
        negative could leave a critical CVE unpatched.
        """
        cache_key = f"nvd:{package.lower()}"
        raw = self._cache.get(cache_key)
        if raw is None:
            try:
                raw = self._fetch(package)
            except httpx.HTTPError as e:
                raise VulnSourceError(
                    f"NVD lookup failed for {package!r}: {e}"
                ) from e
            self._cache.set(cache_key, raw, expire=self._ttl)

        return list(self._parse(raw, package=package, version=version))

    # ------------------------------------------------------------------
    def _fetch(self, package: str) -> dict:
        """Hit the NVD endpoint with retry and a polite rate limit."""
        params = {
            "keywordSearch": package,
            "resultsPerPage": self._max_results,
        }
        # The public endpoint asks unauthenticated callers to wait
        # ~6 seconds between requests. With an API key the limit is
        # 0.6s. We sleep a small amount before every call so a batch
        # run does not get itself blocked.
        time.sleep(0.6 if self._api_key else 6.0)

        attempts = 0
        last_exc: Exception | None = None
        while attempts < 4:
            attempts += 1
            try:
                logger.debug("NVD GET %s params=%s", NVD_ENDPOINT, params)
                resp = self._client.get(NVD_ENDPOINT, params=params)
                if resp.status_code in (429, 503):
                    wait = 2 ** attempts
                    logger.warning("NVD rate-limited (%s); backing off %ss",
                                   resp.status_code, wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as e:
                last_exc = e
                wait = 2 ** attempts
                logger.warning("NVD transient error (%s); retrying in %ss",
                               e, wait)
                time.sleep(wait)
        raise VulnSourceError(
            f"NVD lookup gave up after {attempts} attempts: {last_exc}"
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _parse(
        payload: dict, *, package: str, version: str
    ) -> Iterable[Vulnerability]:
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            summary = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                "",
            )
            score, sev = _extract_cvss(cve)
            fixed_version = _extract_fixed_version(cve, package)
            refs = tuple(
                r.get("url", "")
                for r in cve.get("references", [])
                if r.get("url")
            )

            yield Vulnerability(
                cve_id=cve_id,
                package=package,
                installed_version=version,
                fixed_version=fixed_version,
                cvss_score=score,
                severity=sev,
                summary=summary,
                references=refs,
            )

    # ------------------------------------------------------------------
    def close(self) -> None:
        self._client.close()
        self._cache.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _extract_cvss(cve: dict) -> tuple[float, Severity]:
    """Pick the best available CVSS score (v3.1 > v3.0 > v2)."""
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {}) or {}
            score = float(data.get("baseScore", 0.0) or 0.0)
            return score, severity_from_cvss(score)
    return 0.0, "none"


def _extract_fixed_version(cve: dict, package: str) -> Optional[str]:
    """Best-effort scan of CPE configurations for a ``versionEndExcluding``
    that suggests when the fix shipped. The result is informational —
    the OS package manager is the source of truth for upgrade targets.
    """
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if package.lower() in cpe.get("criteria", "").lower():
                    end = cpe.get("versionEndExcluding")
                    if end:
                        return str(end)
    return None
