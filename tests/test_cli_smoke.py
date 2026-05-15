"""Light-touch CLI smoke tests using click's CliRunner."""

from __future__ import annotations

from click.testing import CliRunner

from patchmgr.cli import cli


def test_cli_help_lists_subcommands():
    r = CliRunner().invoke(cli, ["--help"])
    assert r.exit_code == 0
    for sub in ("scan", "patch", "batch", "report"):
        assert sub in r.output


def test_cli_version():
    r = CliRunner().invoke(cli, ["--version"])
    assert r.exit_code == 0
    assert "patchmgr" in r.output.lower()


def test_scan_help_shows_required_flags():
    r = CliRunner().invoke(cli, ["scan", "--help"])
    assert r.exit_code == 0
    assert "--target" in r.output
    assert "--os" in r.output


def test_patch_requires_at_for_scheduled():
    r = CliRunner().invoke(
        cli,
        ["patch",
         "--os", "linux",
         "--target", "10.0.0.1:admin:hunter2",
         "--reboot", "scheduled"],
    )
    assert r.exit_code != 0
    assert "--at" in r.output or "scheduled" in r.output
