"""Per-OS discovery and remediation handlers.

Every handler implements :class:`patchmgr.handlers.base.OSHandler` so
the engine can drive any operating system through the same set of
calls: detect, list packages, find missing patches, apply patches,
check reboot status.

Concrete handlers:

* :class:`patchmgr.handlers.linux.LinuxHandler`
* :class:`patchmgr.handlers.windows.WindowsHandler`
* :class:`patchmgr.handlers.aix.AIXHandler` (UNVERIFIED on real HW)
"""

from patchmgr.handlers.base import (
    InstalledPackage,
    MissingPatch,
    OSHandler,
    OSInfo,
    PatchResult,
    UnsupportedOSError,
)
from patchmgr.handlers.linux import LinuxHandler
from patchmgr.handlers.windows import WindowsHandler
from patchmgr.handlers.aix import AIXHandler


def build_handler(os_type: str, transport):
    """Factory: return the right handler for *os_type*."""
    os_type = os_type.lower()
    if os_type == "linux":
        return LinuxHandler(transport)
    if os_type == "windows":
        return WindowsHandler(transport)
    if os_type == "aix":
        return AIXHandler(transport)
    raise UnsupportedOSError(f"unsupported OS type: {os_type!r}")


__all__ = (
    "InstalledPackage",
    "MissingPatch",
    "OSHandler",
    "OSInfo",
    "PatchResult",
    "UnsupportedOSError",
    "LinuxHandler",
    "WindowsHandler",
    "AIXHandler",
    "build_handler",
)
