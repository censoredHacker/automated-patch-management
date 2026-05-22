"""Discovery — collect OS facts, installed packages, missing patches."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from patchmgr.handlers.base import (
    InstalledPackage,
    MissingPatch,
    OSHandler,
    OSInfo,
)


logger = logging.getLogger(__name__)


@dataclass
class DiscoveryReport:
    os_info: OSInfo
    installed: list[InstalledPackage]
    missing: list[MissingPatch]


def discover(handler: OSHandler, *, minor_os_upgrade: bool = False) -> DiscoveryReport:
    """Run the full discovery sequence against *handler*.

    All three sub-calls are independent from the engine's perspective
    but share state inside the handler (cached OS detection, etc.) so
    we keep them sequential. Failures bubble up — discovery is the
    foundation of everything else, there is no point in continuing
    past a broken probe.
    """
    os_info = handler.detect()
    logger.info("host facts: %s", os_info.to_dict())

    installed = list(handler.list_packages())
    logger.info("found %d installed packages", len(installed))

    missing = list(handler.list_missing_patches(minor_os_upgrade=minor_os_upgrade))
    logger.info("found %d missing patches", len(missing))

    return DiscoveryReport(os_info=os_info, installed=installed, missing=missing)
