"""Tests for monitor_19 (deception)."""
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


dc = _load("monitor_19")


def test_deploy_and_interact():
    d = dc.Deception()
    cid = d.deploy("credential", "svc-backup")
    hid = d.deploy("host", "db-decoy")
    assert cid != hid
    a = d.interact(cid, "10.0.0.9", "login_attempt", ts=5.0)
    assert a.severity == 95
    assert a.decoy_id == cid
    assert len(d.alerts()) == 1


def test_burn_and_stats():
    d = dc.Deception()
    cid = d.deploy("api_key", "stripe-test")
    d.deploy("share", "finance-decoy")
    d.interact(cid, "s", "use", ts=1.0)
    d.burn(cid)
    s = d.stats()
    assert s["deployed"] == 2
    assert s["active"] == 1
    assert s["interactions"] == 1
    with pytest.raises(dc.DeceptionError):
        d.interact(cid, "s", "use")


def test_fail_closed():
    d = dc.Deception()
    with pytest.raises(dc.DeceptionError):
        d.deploy("nonsense", "x")
    with pytest.raises(dc.DeceptionError):
        d.deploy("host", "")
    with pytest.raises(dc.DeceptionError):
        d.interact("decoy-9999", "s", "i")
    with pytest.raises(dc.DeceptionError):
        d.burn("decoy-9999")


def test_stdlib_only():
    assert dc.stdlib_only() is True
