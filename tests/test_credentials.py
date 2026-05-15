"""Tests for :mod:`patchmgr.credentials`."""

from __future__ import annotations

import pytest

from patchmgr.credentials import CredentialParseError, parse_target


def test_simple_ip_user_password():
    c = parse_target("10.0.0.1:admin:hunter2")
    assert c.host == "10.0.0.1"
    assert c.username == "admin"
    assert c.password == "hunter2"
    assert c.port == 22


def test_ip_port_user_password():
    c = parse_target("10.0.0.1:2222:admin:hunter2")
    assert c.port == 2222
    assert c.username == "admin"
    assert c.password == "hunter2"


def test_password_can_contain_colons():
    c = parse_target("10.0.0.1:admin:complex:pass:word")
    assert c.password == "complex:pass:word"


def test_hostname_accepted():
    c = parse_target("server.example.com:root:secret")
    assert c.host == "server.example.com"


@pytest.mark.parametrize("bad", [
    "",                              # empty
    "no-colons",                     # no separators
    "10.0.0.1:admin",                # missing password
    "::admin:pass",                  # missing host
    "not_a_host!:admin:pass",        # invalid hostname char
    "10.0.0.1:99999:admin:pass",     # port out of range
])
def test_invalid_targets_raise(bad: str):
    with pytest.raises(CredentialParseError):
        parse_target(bad)


def test_safe_repr_does_not_leak_password():
    c = parse_target("10.0.0.1:admin:hunter2")
    assert "hunter2" not in repr(c)
    assert "hunter2" not in str(c)


def test_safe_dict_excludes_secrets():
    c = parse_target("10.0.0.1:admin:hunter2")
    d = c.safe_dict()
    assert "hunter2" not in str(d)
    assert d["auth"] == "password"


def test_key_path_is_accepted_without_password():
    c = parse_target("10.0.0.1:admin:placeholder", key_path="/tmp/id")
    assert c.key_path == "/tmp/id"
