"""Tests for monitor_20 (honeypots)."""
import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


hn = _load("monitor_20")


def test_deploy_and_ban():
    h = hn.Honeynet(ban_threshold=3)
    h.deploy("ssh", "hp1", 2222)
    for i in range(3):
        h.connection("hp1", "9.9.9.9", "auth_attempt", ts=float(i))
    assert h.is_banned("9.9.9.9") is True
    assert any(a.kind == "banned" for a in h.alerts())
    h.connection("hp1", "9.9.9.9", "connect", ts=9.0)
    assert any(a.kind == "banned_ip_retry" for a in h.alerts())


def test_auth_success_critical():
    h = hn.Honeynet()
    h.deploy("ftp", "hp2", 2121)
    h.connection("hp2", "8.8.8.8", "auth_success", ts=1.0)
    assert any(a.kind == "auth_success" and a.severity == 95 for a in h.alerts())


def test_stats():
    h = hn.Honeynet()
    h.deploy("smb", "hp3", 445)
    h.connection("hp3", "1.1.1.1", "connect", ts=1.0)
    s = h.stats()
    assert s == {"honeypots": 1, "events": 1, "banned_ips": 0, "alerts": 0}


def test_fail_closed():
    h = hn.Honeynet()
    with pytest.raises(hn.HoneypotError):
        h.deploy("irc", "x", 80)
    h.deploy("ssh", "hp1", 22)
    with pytest.raises(hn.HoneypotError):
        h.deploy("ssh", "hp1", 23)
    with pytest.raises(hn.HoneypotError):
        h.connection("ghost", "1.1.1.1", "connect")
    with pytest.raises(hn.HoneypotError):
        h.connection("hp1", "1.1.1.1", "bogus")


def test_stdlib_only():
    assert hn.stdlib_only() is True
