"""AIX handler — *UNVERIFIED on real hardware*.

The commands below follow IBM's published documentation for AIX 7.x:

* ``oslevel -s``      — full TL/SP level string
* ``lslpp -Lcq``      — installed filesets, colon-separated
* ``instfix -i``      — list installed APAR fixes
* ``installp -acgXY`` — install + commit + auto-prereq + accept license
* ``shutdown -Fr``    — fast reboot

Because we cannot run a regression test against real AIX hardware,
this handler is **dry-run by default** when invoked through the CLI.
Operators wishing to use it in anger must explicitly pass
``--no-dry-run`` and acknowledge that responsibility.
"""

from __future__ import annotations

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
from patchmgr.utils.shell import sh_quote


logger = logging.getLogger(__name__)


class AIXHandler(OSHandler):
    os_type = "aix"

    def __init__(self, transport: Transport):
        super().__init__(transport)
        self._os_info: OSInfo | None = None

    # ------------------------------------------------------------------
    def detect(self) -> OSInfo:
        if self._os_info:
            return self._os_info

        uname = self._transport.exec("uname -s")
        if uname.stdout.strip() != "AIX":
            raise UnsupportedOSError(
                f"host is not AIX (uname -s = {uname.stdout.strip()!r})"
            )

        oslevel = self._transport.exec("oslevel -s 2>/dev/null").stdout.strip()
        kernel = self._transport.exec("uname -v").stdout.strip()
        arch = self._transport.exec("uname -p 2>/dev/null").stdout.strip()

        self._os_info = OSInfo(
            os_type="aix",
            distro="aix",
            version=oslevel,
            kernel=kernel,
            architecture=arch,
        )
        logger.info("detected AIX %s (kernel=%s, arch=%s) — handler UNVERIFIED",
                    oslevel, kernel, arch)
        return self._os_info

    # ------------------------------------------------------------------
    def list_packages(self) -> Iterable[InstalledPackage]:
        # ``lslpp -Lcq`` outputs colon-separated records; field order:
        # name:fileset:level:state:type:description:...
        res = self._transport.exec("lslpp -Lcq")
        if not res.ok:
            raise TransportError(f"lslpp failed: {res.stderr}")
        out: list[InstalledPackage] = []
        for line in res.stdout.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 3:
                continue
            name, version = parts[1], parts[2]
            if name:
                out.append(InstalledPackage(
                    name=name, version=version, source="lslpp",
                ))
        return out

    # ------------------------------------------------------------------
    def list_missing_patches(self) -> Iterable[MissingPatch]:
        """List APARs known to fix issues on the installed TL/SP.

        ``instfix -ci`` prints CSV: APAR:abstract:status:fileset.
        Anything with status != 'F' (found) is reported as missing.
        """
        res = self._transport.exec("instfix -ci 2>/dev/null || true")
        out: list[MissingPatch] = []
        for line in res.stdout.splitlines():
            if not line or ":" not in line:
                continue
            parts = line.split(":")
            if len(parts) < 4:
                continue
            apar, abstract, status, fileset = parts[0], parts[1], parts[2], parts[3]
            if status.strip().upper() == "F":
                continue  # already installed
            out.append(MissingPatch(
                identifier=apar,
                title=abstract or apar,
                severity="high",
                package=fileset or None,
                reboot_required=True,  # most AIX fixes do
                metadata={"status": status},
            ))
        return out

    # ------------------------------------------------------------------
    def apply_patch(self, patch: MissingPatch, *, dry_run: bool) -> PatchResult:
        if dry_run:
            return PatchResult(
                patch=patch, success=True,
                stdout="dry-run: no changes applied (AIX handler is unverified)",
            )
        # Real-world AIX patching usually targets a NIM lpp_source or
        # a local directory. We expose the fileset name; the operator
        # is expected to have prepared the install source. We default
        # to /usr/sys/inst.images which is the historical convention.
        target = sh_quote(patch.package or patch.identifier)
        cmd = f"installp -acgXY -d /usr/sys/inst.images {target}"
        start = time.monotonic()
        try:
            res = self._transport.exec(cmd, timeout=1800)
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
        # AIX does not expose a standard "reboot required" flag. The
        # conservative answer is "yes if any fileset install logged
        # the bosboot flag", which we cannot infer remotely after the
        # fact. Treat as True so operators schedule a window.
        return True

    def reboot(self, *, delay_minutes: int = 0) -> None:
        # ``shutdown -Fr +N`` is the AIX equivalent; -F = fast.
        cmd = (
            "shutdown -Fr now 'patchmgr automated reboot'"
            if delay_minutes <= 0
            else f"shutdown -Fr +{delay_minutes} 'patchmgr automated reboot'"
        )
        logger.warning("issuing AIX reboot (delay=%dmin)", delay_minutes)
        try:
            self._transport.exec(cmd, timeout=15)
        except TransportError:
            pass
