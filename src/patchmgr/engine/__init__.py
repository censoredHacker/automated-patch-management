"""Engine — orchestrates the scan/patch lifecycle.

* :mod:`patchmgr.engine.discovery`   — gather OS facts + installed packages
* :mod:`patchmgr.engine.prioritizer` — apply CVE intel + severity filter
* :mod:`patchmgr.engine.remediator`  — drive handler.apply_patch with retries
* :mod:`patchmgr.engine.reboot`      — auto/scheduled/manual reboot strategy
* :mod:`patchmgr.engine.runner`      — top-level "do everything" entrypoint
"""

from patchmgr.engine.runner import run_scan, run_patch, RunOptions

__all__ = ("run_scan", "run_patch", "RunOptions")
