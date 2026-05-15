"""Linux handler tests using the FakeTransport fixture."""

from __future__ import annotations

from patchmgr.handlers.linux import LinuxHandler


_OS_RELEASE = """\
NAME="Ubuntu"
VERSION="22.04 LTS"
ID=ubuntu
VERSION_ID="22.04"
"""


def _setup_ubuntu(ft):
    ft.register("cat /etc/os-release", stdout=_OS_RELEASE)
    ft.register("uname -r", stdout="5.15.0-86-generic\n")
    ft.register("uname -m", stdout="x86_64\n")
    # apt is the first thing tried after dnf/yum, so mark dnf/yum missing.
    ft.register("command -v dnf", stdout="1\n")
    ft.register("command -v yum", stdout="1\n")
    ft.register("command -v apt", stdout="0\n")


def test_detect_ubuntu(fake_transport):
    _setup_ubuntu(fake_transport)
    h = LinuxHandler(fake_transport)
    info = h.detect()
    assert info.distro == "ubuntu"
    assert info.version == "22.04"
    assert info.kernel.startswith("5.15")
    assert h._pm_key == "apt"


def test_list_packages_dpkg(fake_transport):
    _setup_ubuntu(fake_transport)
    fake_transport.register(
        "dpkg-query",
        stdout="openssh-server\t1:8.9p1-3ubuntu0.4\nlibc6\t2.35-0ubuntu3.4\n",
    )
    h = LinuxHandler(fake_transport)
    h.detect()
    pkgs = list(h.list_packages())
    assert len(pkgs) == 2
    assert pkgs[0].name == "openssh-server"
    assert pkgs[1].version.startswith("2.35")


def test_apt_simulation_parser(fake_transport):
    _setup_ubuntu(fake_transport)
    fake_transport.register(
        "apt-get -s",
        stdout=(
            "Reading package lists...\n"
            "Inst openssh-server [1:8.9p1-3ubuntu0.4] (1:8.9p1-3ubuntu0.10 Ubuntu:22.04/jammy-updates [amd64])\n"
            "Inst libc6 [2.35-0ubuntu3.4] (2.35-0ubuntu3.6 Ubuntu:22.04/jammy-updates [amd64])\n"
        ),
    )
    h = LinuxHandler(fake_transport)
    h.detect()
    missing = list(h.list_missing_patches())
    ids = {m.identifier for m in missing}
    assert ids == {"openssh-server", "libc6"}
    libc = next(m for m in missing if m.identifier == "libc6")
    assert libc.current_version.startswith("2.35-0ubuntu3.4")
    assert libc.target_version.startswith("2.35-0ubuntu3.6")


def test_apply_patch_dry_run_does_not_call_apt(fake_transport):
    _setup_ubuntu(fake_transport)
    h = LinuxHandler(fake_transport)
    h.detect()
    from patchmgr.handlers.base import MissingPatch
    result = h.apply_patch(
        MissingPatch(identifier="openssh-server", package="openssh-server"),
        dry_run=True,
    )
    assert result.success
    assert "dry-run" in result.stdout
    # Verify we never issued the install command.
    assert not any("apt-get install" in cmd for cmd in fake_transport.history)


def test_reboot_required_detects_debian_sentinel(fake_transport):
    _setup_ubuntu(fake_transport)
    fake_transport.register("test -f /var/run/reboot-required", stdout="yes\n")
    h = LinuxHandler(fake_transport)
    h.detect()
    assert h.reboot_required() is True
