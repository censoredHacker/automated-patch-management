"""Plain-old-data classes that travel from the engine to the reporters.

Kept as `dataclass`es (not pydantic models) because they are produced
inside hot loops and never validated again — pydantic's overhead
buys nothing here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from patchmgr import __version__


@dataclass
class RunMetadata:
    run_id: str
    action: str  # 'scan' | 'patch'
    started_at: str
    finished_at: Optional[str] = None
    duration_seconds: float = 0.0
    tool_version: str = __version__

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "action": self.action,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "tool_version": self.tool_version,
        }


@dataclass
class HostReport:
    metadata: RunMetadata
    target: dict
    os_info: dict
    installed_packages_count: int
    prioritized_patches: list[dict] = field(default_factory=list)
    applied_patches: list[dict] = field(default_factory=list)
    reboot: Optional[dict] = None

    # ------------------------------------------------------------------
    # Convenience aggregates used by the HTML template & summary line.
    # ------------------------------------------------------------------
    @property
    def patches_total(self) -> int:
        return len(self.applied_patches)

    @property
    def patches_succeeded(self) -> int:
        return sum(1 for p in self.applied_patches if p.get("success"))

    @property
    def patches_failed(self) -> int:
        return self.patches_total - self.patches_succeeded

    @property
    def success_rate(self) -> float:
        if self.patches_total == 0:
            return 100.0 if not self.prioritized_patches else 0.0
        return round(100.0 * self.patches_succeeded / self.patches_total, 2)

    def to_dict(self) -> dict[str, object]:
        return {
            "metadata": self.metadata.to_dict(),
            "target": self.target,
            "os_info": self.os_info,
            "installed_packages_count": self.installed_packages_count,
            "prioritized_patches": self.prioritized_patches,
            "applied_patches": self.applied_patches,
            "reboot": self.reboot,
            "summary": {
                "patches_total": self.patches_total,
                "patches_succeeded": self.patches_succeeded,
                "patches_failed": self.patches_failed,
                "success_rate_percent": self.success_rate,
            },
        }
