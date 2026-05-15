"""Thin wrapper around :mod:`tenacity` with project-wide defaults.

The rest of the codebase calls :func:`with_retry` rather than touching
tenacity directly so that retry semantics (max attempts, backoff
curve, what to log) are consistent across every remote operation.
"""

from __future__ import annotations

import logging
from typing import Callable, TypeVar

from tenacity import (
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)

T = TypeVar("T")

logger = logging.getLogger(__name__)


def with_retry(
    func: Callable[..., T],
    *args,
    max_attempts: int = 3,
    initial_backoff: float = 2.0,
    max_backoff: float = 30.0,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
    **kwargs,
) -> T:
    """Call *func* up to *max_attempts* times with exponential backoff.

    The intent is to absorb *transient* failures (network blips, lock
    contention on a package database) without papering over real bugs.
    Callers should pass a narrow ``retry_on`` tuple — defaulting to
    ``Exception`` is convenient for prototypes but will hide
    programming errors.
    """
    retryer = Retrying(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=initial_backoff, max=max_backoff),
        retry=retry_if_exception_type(retry_on),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    for attempt in retryer:
        with attempt:
            return func(*args, **kwargs)
    raise RuntimeError("unreachable")  # pragma: no cover
