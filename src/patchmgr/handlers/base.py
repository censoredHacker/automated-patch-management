"""OS handler ABC and shared data classes.

A *handler* is the OS-specific bit of patchmgr. It knows which shell
commands to run to gather facts, what the package manager is called,
and how to ask "do you need a reboot?".

The engine never imports concrete handlers — it goes through
:func:`patchmgr.handlers.build_handler` so adding a new OS later is a
single-file change.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Iterable, Optional


class UnsupportedOSError(Exception):
    """Raised for OS versions/distributions we cannot handle."""


@dataclass(frozen=True)
class OSInfo:
    """High-level facts about the remote host."""

    os_type: str          # 'linux' | 'windows' | 'aix'
    distro: str           # 'ubuntu', 'rhel', 'sles', 'windows', 'aix', ...
    version: str          # e.g. '22.04', '8.9', '2019', '7.2'
    kernel: str = ""      # uname -r equivalent (empty on Windows)
    architecture: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "os_type": self.os_type,
            "distro": self.distro,
            "version": self.version,
            "kernel": self.kernel,
            "architecture": self.architecture,
        }


@dataclass(frozen=True)
class InstalledPackage:
    """One installed software component as discovered on the host."""

    name: str
    version: str
    source: str = ""  # 'rpm', 'dpkg', 'msu', 'lslpp', ...

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version, "source": self.source}


@dataclass(frozen=True)
class MissingPatch:
    """A patch the host is missing.

    For Linux this is typically a package update (name + target
    version). For Windows it is a KB article. For AIX an APAR or
    fileset. We model them uniformly so the report layer can present
    them side-by-side.
    """

    identifier: str            # KB number, APAR, package name
    title: str = ""
    severity: str = "unknown"  # 'critical' | 'high' | 'medium' | 'low' | 'unknown'
    package: Optional[str] = None
    current_version: Optional[str] = None
    target_version: Optional[str] = None
    reboot_required: bool = False
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "identifier": self.identifier,
            "title": self.title,
            "severity": self.severity,
            "package": self.package,
            "current_version": self.current_version,
            "target_version": self.target_version,
            "reboot_required": self.reboot_required,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class PatchResult:
    """Outcome of applying (or attempting to apply) a single patch."""

    patch: MissingPatch
    success: bool
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        return {
            "patch": self.patch.to_dict(),
            "success": self.success,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            # stdout/stderr trimmed in the report to keep size sane
            "stdout_tail": self.stdout[-2000:] if self.stdout else "",
            "stderr_tail": self.stderr[-2000:] if self.stderr else "",
        }


class OSHandler(abc.ABC):
    """ABC every per-OS handler implements."""

    os_type: str = ""

    def __init__(self, transport):
        self._transport = transport

    # ---- discovery ----------------------------------------------------
    @abc.abstractmethod
    def detect(self) -> OSInfo: ...

    @abc.abstractmethod
    def list_packages(self) -> Iterable[InstalledPackage]: ...

    @abc.abstractmethod
    def list_missing_patches(self) -> Iterable[MissingPatch]: ...

    # ---- remediation --------------------------------------------------
    @abc.abstractmethod
    def apply_patch(self, patch: MissingPatch, *, dry_run: bool) -> PatchResult: ...

    # ---- reboot -------------------------------------------------------
    @abc.abstractmethod
    def reboot_required(self) -> bool: ...

    @abc.abstractmethod
    def reboot(self, *, delay_minutes: int = 0) -> None: ...
