"""Windows handler — discovery + remediation via PSWindowsUpdate.

`PSWindowsUpdate` is the de-facto standard PowerShell module for
driving Windows Update from a script. If the module is missing on the
target host we install it from the PowerShell Gallery into the
current user scope — that requires `Install-Module`, which in turn
requires TLS 1.2 on older Server 2012/2016 boxes (we set it).

All PowerShell snippets are wrapped in `try/catch` and emit JSON to
stdout so we never have to parse free-form table output.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Iterable

from patchmgr.handlers.base import (
    InstalledPackage,
    MissingPatch,
    OSHandler,
    OSInfo,
    PatchResult,
    UnsupportedOSError,
)
from patchmgr.transport import Transport, TransportError


logger = logging.getLogger(__name__)


_DETECT_PS = r"""
$ErrorActionPreference = 'Stop'
$ci = Get-CimInstance Win32_OperatingSystem
$out = [PSCustomObject]@{
    Caption          = $ci.Caption
    Version          = $ci.Version
    BuildNumber      = $ci.BuildNumber
    OSArchitecture   = $ci.OSArchitecture
    CSDVersion       = $ci.CSDVersion
}
$out | ConvertTo-Json -Compress
"""


_LIST_HOTFIXES_PS = r"""
$ErrorActionPreference = 'Stop'
Get-HotFix | Select-Object HotFixID, Description, InstalledOn |
    ConvertTo-Json -Compress -Depth 3
"""


_ENSURE_PSWU_PS = r"""
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol =
    [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
    Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber | Out-Null
}
Import-Module PSWindowsUpdate
'OK'
"""


_LIST_UPDATES_PS = r"""
$ErrorActionPreference = 'Stop'
Import-Module PSWindowsUpdate
Get-WindowsUpdate -MicrosoftUpdate -IgnoreReboot -ErrorAction Stop |
    Select-Object KB, Title, Size, MsrcSeverity, RebootRequired |
    ConvertTo-Json -Compress -Depth 4
"""


_INSTALL_KB_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
Import-Module PSWindowsUpdate
Get-WindowsUpdate -KBArticleID '{kb}' -Install -AcceptAll -IgnoreReboot `
    -MicrosoftUpdate -ErrorAction Stop |
    Select-Object KB, Result, Title |
    ConvertTo-Json -Compress -Depth 4
"""


_REBOOT_REQUIRED_PS = r"""
$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
)
$pending = $false
foreach ($p in $paths) { if (Test-Path $p) { $pending = $true } }
if ($pending) { 'yes' } else { 'no' }
"""


def _severity_from_msrc(value: str | None) -> str:
    """Map Microsoft MSRC severity strings to our internal vocabulary."""
    if not value:
        return "unknown"
    v = value.strip().lower()
    if v == "critical":
        return "critical"
    if v == "important":
        return "high"
    if v == "moderate":
        return "medium"
    if v == "low":
        return "low"
    return "unknown"


class WindowsHandler(OSHandler):
    os_type = "windows"

    def __init__(self, transport: Transport):
        super().__init__(transport)
        self._os_info: OSInfo | None = None
        self._pswu_ready = False

    # ------------------------------------------------------------------
    def detect(self) -> OSInfo:
        if self._os_info:
            return self._os_info
        res = self._transport.exec(_DETECT_PS)
        if not res.ok:
            raise UnsupportedOSError(f"could not detect Windows: {res.stderr}")
        try:
            data = json.loads(res.stdout.strip() or "{}")
        except json.JSONDecodeError as e:
            raise UnsupportedOSError(f"unexpected Get-CimInstance output: {e}") from e
        self._os_info = OSInfo(
            os_type="windows",
            distro="windows",
            version=str(data.get("Version", "")),
            kernel=f"build {data.get('BuildNumber', '')}",
            architecture=str(data.get("OSArchitecture", "")),
        )
        logger.info("detected Windows %s (%s)",
                    self._os_info.version, data.get("Caption", ""))
        return self._os_info

    # ------------------------------------------------------------------
    def list_packages(self) -> Iterable[InstalledPackage]:
        """Return installed hotfixes. Win32_Product is intentionally
        avoided because it triggers an MSI consistency check that can
        take many minutes on busy servers.
        """
        res = self._transport.exec(_LIST_HOTFIXES_PS)
        if not res.ok:
            raise TransportError(f"Get-HotFix failed: {res.stderr}")
        try:
            data = json.loads(res.stdout or "[]")
        except json.JSONDecodeError:
            return []
        if isinstance(data, dict):
            data = [data]
        out = []
        for entry in data:
            kb = entry.get("HotFixID") or ""
            out.append(InstalledPackage(
                name=kb,
                version=str(entry.get("InstalledOn", "")),
                source="hotfix",
            ))
        return out

    # ------------------------------------------------------------------
    def list_missing_patches(self, *, minor_os_upgrade: bool = False) -> Iterable[MissingPatch]:
        self._ensure_pswu()
        res = self._transport.exec(_LIST_UPDATES_PS, timeout=600)
        if not res.ok:
            raise TransportError(f"Get-WindowsUpdate failed: {res.stderr}")
        if not res.stdout.strip():
            return []
        try:
            data = json.loads(res.stdout)
        except json.JSONDecodeError as e:
            raise TransportError(
                f"could not parse Get-WindowsUpdate JSON: {e}"
            ) from e
        if isinstance(data, dict):
            data = [data]
        
        from dataclasses import replace
        out: list[MissingPatch] = []
        for u in data:
            kb_raw = u.get("KB")
            kb = kb_raw if isinstance(kb_raw, str) else (
                kb_raw[0] if isinstance(kb_raw, list) and kb_raw else ""
            )
            kb = kb or ""
            patch = MissingPatch(
                identifier=kb.replace("KB", "") or u.get("Title", "unknown"),
                title=u.get("Title", ""),
                severity=_severity_from_msrc(u.get("MsrcSeverity")),
                package=kb or None,
                reboot_required=bool(u.get("RebootRequired")),
                metadata={"size_bytes": u.get("Size")},
            )
            if minor_os_upgrade:
                patch = replace(patch, severity="high", metadata={**patch.metadata, "minor_os_upgrade": True})
            out.append(patch)
        return out

    # ------------------------------------------------------------------
    def apply_patch(self, patch: MissingPatch, *, dry_run: bool) -> PatchResult:
        if dry_run:
            return PatchResult(
                patch=patch, success=True,
                stdout="dry-run: no changes applied",
            )
        self._ensure_pswu()
        kb = patch.identifier.lstrip("KB").lstrip("kb")
        if not kb.isdigit():
            return PatchResult(
                patch=patch, success=False,
                error=f"cannot derive KB number from identifier {patch.identifier!r}",
            )
        cmd = _INSTALL_KB_TEMPLATE.format(kb=kb)
        start = time.monotonic()
        try:
            res = self._transport.exec(cmd, timeout=3600)
        except TransportError as e:
            return PatchResult(
                patch=patch, success=False, error=str(e),
                duration_seconds=time.monotonic() - start,
            )
        return PatchResult(
            patch=patch,
            success=res.ok,
            stdout=res.stdout,
            stderr=res.stderr,
            duration_seconds=res.duration_seconds,
            error=None if res.ok else f"exit={res.exit_code}",
        )

    # ------------------------------------------------------------------
    def reboot_required(self) -> bool:
        res = self._transport.exec(_REBOOT_REQUIRED_PS)
        return res.stdout.strip().lower() == "yes"

    def reboot(self, *, delay_minutes: int = 0) -> None:
        seconds = max(delay_minutes * 60, 0)
        cmd = f"shutdown.exe /r /t {seconds} /c \"patchmgr automated reboot\""
        logger.warning("issuing Windows reboot (delay=%dmin)", delay_minutes)
        try:
            self._transport.exec(cmd, timeout=15)
        except TransportError:
            pass

    # ------------------------------------------------------------------
    def _ensure_pswu(self) -> None:
        if self._pswu_ready:
            return
        res = self._transport.exec(_ENSURE_PSWU_PS, timeout=900)
        if not res.ok or "OK" not in res.stdout:
            raise TransportError(
                f"could not load PSWindowsUpdate: {res.stderr or res.stdout}"
            )
        self._pswu_ready = True
