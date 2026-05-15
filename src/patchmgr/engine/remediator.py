"""Remediator — apply patches with retry, accumulate results.

Failures on a single patch are isolated: the engine keeps going and
records the failure in the report. This is the right behaviour for
batch runs where one bad patch should not block the rest of the
queue.
"""

from __future__ import annotations

import logging
from typing import Iterable

from patchmgr.engine.prioritizer import EnrichedPatch
from patchmgr.handlers.base import OSHandler, PatchResult
from patchmgr.utils.retry import with_retry


logger = logging.getLogger(__name__)


def apply_all(
    handler: OSHandler,
    patches: Iterable[EnrichedPatch],
    *,
    dry_run: bool,
    max_attempts: int = 3,
) -> list[PatchResult]:
    """Apply every patch in *patches* using *handler*. Returns one
    :class:`PatchResult` per input — never raises for individual
    failures.
    """
    results: list[PatchResult] = []
    for ep in patches:
        logger.info(
            "applying patch %s (severity=%s, dry_run=%s)",
            ep.patch.identifier, ep.effective_severity, dry_run,
        )
        try:
            result = with_retry(
                handler.apply_patch,
                ep.patch,
                dry_run=dry_run,
                max_attempts=max_attempts,
            )
        except Exception as e:  # noqa: BLE001 - bottom of the stack
            logger.exception("patch %s raised", ep.patch.identifier)
            result = PatchResult(patch=ep.patch, success=False, error=str(e))
        if result.success:
            logger.info("patch %s OK in %.1fs",
                        ep.patch.identifier, result.duration_seconds)
        else:
            logger.error("patch %s FAILED: %s",
                         ep.patch.identifier, result.error)
        results.append(result)
    return results
