"""Report writers — turn engine outputs into JSON + HTML artefacts.

Public surface:

* :class:`HostReport`            — dataclass for a single host's run.
* :func:`write_reports`          — write `report.json` and `report.html`
  into a per-run directory.
"""

from patchmgr.reporting.models import HostReport, RunMetadata
from patchmgr.reporting.writer import write_reports

__all__ = ("HostReport", "RunMetadata", "write_reports")
