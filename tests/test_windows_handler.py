"""Windows handler tests using the FakeTransport fixture."""

from __future__ import annotations

import json

from patchmgr.handlers.windows import WindowsHandler


_DETECT_JSON = json.dumps({
    "Caption": "Microsoft Windows Server 2019 Standard",
    "Version": "10.0.17763",
    "BuildNumber": "17763",
    "OSArchitecture": "64-bit",
    "CSDVersion": None,
})

_GET_WU_JSON = json.dumps([
    {
        "KB": "KB5031361",
        "Title": "2023-10 Cumulative Update",
        "Size": 1234567,
        "MsrcSeverity": "Critical",
        "RebootRequired": True,
    },
    {
        "KB": "KB5028951",
        "Title": "Servicing Stack Update",
        "Size": 1024,
        "MsrcSeverity": "Important",
        "RebootRequired": False,
    },
])


def test_detect_parses_json(fake_transport):
    fake_transport.register_match(
        lambda c: "Win32_OperatingSystem" in c, stdout=_DETECT_JSON,
    )
    h = WindowsHandler(fake_transport)
    info = h.detect()
    assert info.os_type == "windows"
    assert info.version == "10.0.17763"
    assert info.kernel == "build 17763"


def test_list_missing_patches(fake_transport):
    fake_transport.register_match(
        lambda c: "Win32_OperatingSystem" in c, stdout=_DETECT_JSON,
    )
    fake_transport.register_match(
        lambda c: "[Net.ServicePointManager]" in c, stdout="OK",
    )
    fake_transport.register_match(
        lambda c: "Get-WindowsUpdate" in c and "-Install" not in c,
        stdout=_GET_WU_JSON,
    )
    h = WindowsHandler(fake_transport)
    h.detect()
    patches = list(h.list_missing_patches())
    assert len(patches) == 2
    crit = next(p for p in patches if p.identifier == "5031361")
    assert crit.severity == "critical"
    assert crit.reboot_required is True
    high = next(p for p in patches if p.identifier == "5028951")
    assert high.severity == "high"


def test_dry_run_apply(fake_transport):
    h = WindowsHandler(fake_transport)
    from patchmgr.handlers.base import MissingPatch
    result = h.apply_patch(
        MissingPatch(identifier="5031361"), dry_run=True,
    )
    assert result.success
    # No PowerShell install commands issued.
    assert not any("Get-WindowsUpdate" in c and "-Install" in c
                   for c in fake_transport.history)


def test_reboot_required_yes(fake_transport):
    fake_transport.register_match(
        lambda c: "RebootPending" in c, stdout="yes",
    )
    h = WindowsHandler(fake_transport)
    assert h.reboot_required() is True
