"""Linux handler — auto-detects yum / dnf / apt / zypper.

The handler runs lightweight detection probes on connect:

1. Parse ``/etc/os-release`` for the distro family.
2. Pick the first package manager binary that exists in ``$PATH``.
3. Cache the choice so subsequent calls don't re-probe.

All package operations use ``sudo -n`` (non-interactive) so the tool
fails fast if the SSH user does not have passwordless privilege
escalation. We do **not** prompt for a sudo password remotely — that
is unsafe and breaks automation.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Iterable, Optional

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


# Maps a distro family to (package-manager binary, update-cmd, list-installed-cmd, list-updates-cmd)
_PM_TABLE: dict[str, dict[str, str]] = {
    "dnf": {
        "bin": "dnf",
        "list_installed": "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'",
        "list_updates": "dnf -q --refresh check-update --security || true",
        "list_updates_all": "dnf -q --refresh check-update || true",
        "update_one": "sudo -n dnf -y --security update {pkg}",
        "update_one_all": "sudo -n dnf -y update {pkg}",
        "update_all": "sudo -n dnf -y --security update",
    },
    "yum": {
        "bin": "yum",
        "list_installed": "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'",
        "list_updates": "yum -q --security check-update || true",
        "list_updates_all": "yum -q check-update || true",
        "update_one": "sudo -n yum -y --security update {pkg}",
        "update_one_all": "sudo -n yum -y update {pkg}",
        "update_all": "sudo -n yum -y --security update",
    },
    "apt": {
        "bin": "apt-get",
        "list_installed": "dpkg-query -W -f='${Package}\\t${Version}\\n'",
        # `unattended-upgrades --dry-run` would be more accurate but is
        # not present everywhere. apt-get -s gives a reliable simulation.
        "list_updates": "apt-get -s -o Debug::NoLocking=true upgrade",
        "update_one": "sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade {pkg}",
        "update_all": "sudo -n DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",
    },
    "zypper": {
        "bin": "zypper",
        "list_installed": "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'",
        "list_updates": "zypper --non-interactive list-patches --category security",
        "list_updates_all": "zypper --non-interactive list-updates || true",
        "update_one": "sudo -n zypper --non-interactive patch --category security {pkg}",
        "update_one_all": "sudo -n zypper --non-interactive update -y {pkg}",
        "update_all": "sudo -n zypper --non-interactive patch --category security",
    },
}


class LinuxHandler(OSHandler):
    os_type = "linux"

    def __init__(self, transport: Transport):
        super().__init__(transport)
        self._os_info: Optional[OSInfo] = None
        self._pm_key: Optional[str] = None

    # ------------------------------------------------------------------
    def detect(self) -> OSInfo:
        if self._os_info:
            return self._os_info

        # Read os-release for distro id + version.
        res = self._transport.exec("cat /etc/os-release 2>/dev/null || true")
        info = _parse_os_release(res.stdout)
        if not info.get("ID"):
            raise UnsupportedOSError(
                "could not parse /etc/os-release; host may not be Linux"
            )

        kernel = self._transport.exec("uname -r").stdout.strip()
        arch = self._transport.exec("uname -m").stdout.strip()

        self._os_info = OSInfo(
            os_type="linux",
            distro=info.get("ID", "unknown"),
            version=info.get("VERSION_ID", ""),
            kernel=kernel,
            architecture=arch,
        )

        # Pick a package manager. Order matters: prefer dnf over yum.
        for pm in ("dnf", "yum", "apt", "zypper"):
            probe = self._transport.exec(f"command -v {pm} >/dev/null 2>&1; echo $?")
            if probe.stdout.strip() == "0":
                self._pm_key = pm
                break
        if not self._pm_key:
            raise UnsupportedOSError(
                f"no supported package manager found on {self._os_info.distro}"
            )
        logger.info(
            "detected %s %s (kernel=%s, pm=%s)",
            self._os_info.distro,
            self._os_info.version,
            self._os_info.kernel,
            self._pm_key,
        )
        return self._os_info

    # ------------------------------------------------------------------
    def list_packages(self) -> Iterable[InstalledPackage]:
        self._ensure_detected()
        cfg = _PM_TABLE[self._pm_key]  # type: ignore[index]
        res = self._transport.exec(cfg["list_installed"])
        if not res.ok:
            raise TransportError(
                f"failed to list installed packages: {res.stderr}"
            )
        return list(_parse_name_version_lines(res.stdout, source=self._pm_key or ""))

    # ------------------------------------------------------------------
    def list_missing_patches(self, *, minor_os_upgrade: bool = False) -> Iterable[MissingPatch]:
        self._ensure_detected()
        pm = self._pm_key
        cfg = _PM_TABLE[pm]  # type: ignore[index]
        cmd_key = "list_updates_all" if (minor_os_upgrade and "list_updates_all" in cfg) else "list_updates"
        res = self._transport.exec(cfg[cmd_key])
        
        from dataclasses import replace
        
        if pm in ("yum", "dnf"):
            patches = list(_parse_yum_dnf_updates(res.stdout))
        elif pm == "apt":
            patches = list(_parse_apt_simulation(res.stdout))
        elif pm == "zypper":
            patches = list(_parse_zypper_patches(res.stdout, minor_os_upgrade=minor_os_upgrade))
        else:
            patches = []
            
        if minor_os_upgrade:
            return [
                replace(p, severity="high", metadata={**p.metadata, "minor_os_upgrade": True})
                for p in patches
            ]
        return patches

    # ------------------------------------------------------------------
    def apply_patch(self, patch: MissingPatch, *, dry_run: bool) -> PatchResult:
        self._ensure_detected()
        cfg = _PM_TABLE[self._pm_key]  # type: ignore[index]
        if dry_run:
            logger.info("[dry-run] would patch %s on %s",
                        patch.identifier, self._pm_key)
            return PatchResult(
                patch=patch,
                success=True,
                stdout="dry-run: no changes applied",
                duration_seconds=0.0,
            )
        minor_os_upgrade = patch.metadata.get("minor_os_upgrade", False)
        cmd_key = "update_one_all" if (minor_os_upgrade and "update_one_all" in cfg) else "update_one"
        cmd = cfg[cmd_key].format(pkg=sh_quote(patch.identifier))
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
        # Several distros expose a sentinel file or a tool. We try a
        # few in order and treat any positive signal as "yes".
        probes = (
            # Debian/Ubuntu
            "test -f /var/run/reboot-required && echo yes || true",
            # RHEL-family (needs-restarting -r returns 1 when reboot needed)
            "command -v needs-restarting >/dev/null 2>&1 "
            "&& (needs-restarting -r >/dev/null 2>&1; "
            "[ $? -eq 1 ] && echo yes) || true",
            # SUSE
            "command -v zypper >/dev/null 2>&1 "
            "&& zypper ps -s >/dev/null 2>&1 && echo maybe || true",
        )
        for p in probes:
            r = self._transport.exec(p)
            if "yes" in r.stdout:
                return True
        return False

    def reboot(self, *, delay_minutes: int = 0) -> None:
        if delay_minutes <= 0:
            cmd = "sudo -n shutdown -r now 'patchmgr automated reboot'"
        else:
            cmd = f"sudo -n shutdown -r +{delay_minutes} 'patchmgr automated reboot'"
        logger.warning("issuing reboot on %s (delay=%dmin)",
                       self._os_info.distro if self._os_info else "host", delay_minutes)
        # We do not wait for the command to return cleanly — the SSH
        # session will drop when the box goes down. Surface the
        # underlying error only if we never got the request out.
        try:
            self._transport.exec(cmd, timeout=15)
        except TransportError:
            pass

    # ------------------------------------------------------------------
    def _ensure_detected(self) -> None:
        if not self._os_info or not self._pm_key:
            self.detect()


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------
def _parse_os_release(text: str) -> dict[str, str]:
    """Parse the ``key=value`` lines of /etc/os-release into a dict."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _parse_name_version_lines(text: str, *, source: str) -> Iterable[InstalledPackage]:
    """Parse ``name<TAB>version`` lines into InstalledPackage objects."""
    for raw in text.splitlines():
        if "\t" not in raw:
            continue
        name, version = raw.split("\t", 1)
        name, version = name.strip(), version.strip()
        if name:
            yield InstalledPackage(name=name, version=version, source=source)


_YUM_DNF_UPDATE_RE = re.compile(r"^([A-Za-z0-9._+\-]+)\.([A-Za-z0-9_]+)\s+(\S+)\s+(\S+)")


def _parse_yum_dnf_updates(text: str) -> Iterable[MissingPatch]:
    """`yum/dnf check-update` prints `name.arch  version  repo` lines.

    Header text and blank lines are skipped. Anything that does not
    match the expected shape is ignored rather than failing — package
    manager output is notoriously formatting-fragile.
    """
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith(("Last metadata", "Obsoleting", "Security:")):
            continue
        m = _YUM_DNF_UPDATE_RE.match(line)
        if not m:
            continue
        name, _arch, ver, _repo = m.groups()
        yield MissingPatch(
            identifier=name,
            title=f"Update {name} to {ver}",
            severity="high",  # check-update --security filters to security only
            package=name,
            target_version=ver,
            reboot_required=name.startswith(("kernel", "glibc", "systemd")),
        )


def _parse_apt_simulation(text: str) -> Iterable[MissingPatch]:
    """`apt-get -s upgrade` prints `Inst <pkg> [old] (new ...)` lines."""
    pat = re.compile(
        r"^Inst\s+(\S+)\s+\[(\S+)\]\s+\((\S+)\s"
    )
    for line in text.splitlines():
        m = pat.match(line)
        if not m:
            continue
        name, old, new = m.groups()
        yield MissingPatch(
            identifier=name,
            title=f"Upgrade {name}: {old} -> {new}",
            severity="high",
            package=name,
            current_version=old,
            target_version=new,
            reboot_required=name.startswith(("linux-image", "libc6", "systemd")),
        )


def _parse_zypper_patches(text: str, *, minor_os_upgrade: bool = False) -> Iterable[MissingPatch]:
    """`zypper list-patches` or `zypper list-updates` prints a pipe-delimited table."""
    for line in text.splitlines():
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4 or parts[0].lower() in ("repository", "---"):
            continue
        name = parts[1]
        if minor_os_upgrade:
            # zypper list-updates columns: Repository | Name | Current Version | Available Version | Arch
            yield MissingPatch(
                identifier=name,
                title=f"Upgrade {name} to {parts[3] if len(parts) > 3 else 'latest'}",
                severity="high",
                package=name,
                reboot_required=name.startswith(("kernel", "glibc", "systemd")),
            )
        else:
            if len(parts) < 6:
                continue
            # repo | name | category | severity | interactive | status
            category, severity = parts[2], parts[3]
            if category.lower() != "security":
                continue
            yield MissingPatch(
                identifier=name,
                title=f"SUSE security patch {name}",
                severity=severity.lower() if severity else "high",
                package=name,
                reboot_required="reboot" in (parts[4] or "").lower(),
            )
