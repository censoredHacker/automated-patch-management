"""Construct a :class:`VulnSource` from validated settings."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from patchmgr.config import VulnSourceSettings
from patchmgr.vulnsource.base import VulnSource, VulnSourceError
from patchmgr.vulnsource.local_json import LocalJSONSource
from patchmgr.vulnsource.nvd import NVDSource


logger = logging.getLogger(__name__)


def build_vuln_source(
    settings: VulnSourceSettings,
    *,
    cache_dir: Optional[Path] = None,
) -> VulnSource:
    """Return a concrete :class:`VulnSource` from *settings*."""
    if settings.provider == "nvd":
        logger.info("vulnerability source: NVD 2.0")
        return NVDSource(
            cache_dir=cache_dir,
            cache_ttl_hours=settings.cache_ttl_hours,
        )
    if settings.provider == "local_json":
        if settings.local_path is None:
            raise VulnSourceError(
                "vulnerability_source.local_path is required when "
                "provider == 'local_json'"
            )
        logger.info("vulnerability source: local_json (%s)", settings.local_path)
        return LocalJSONSource(settings.local_path)
    raise VulnSourceError(
        f"unknown vulnerability source provider: {settings.provider}"
    )
