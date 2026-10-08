"""Tests for monitor_15 (UEBA)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


ue = _load("monitor_15")


def test_risk_accumulates_and_flags():
    u = ue.Ueba(half_life_s=3600, high_threshold=70)
    u.ingest("a", "failed_login")
    u.ingest("a", "failed_login")
    u.ingest("a", "new_device")
    u.ingest("a", "privilege_use")
    assert u.flagged("a") is False
    u.ingest("a", "unusual_hour", hour=3)
    u.ingest("a", "new_ip")
    assert u.flagged("a") is True


def test_success_resets_failures():
    import pytest as _pytest

    u = ue.Ueba()
    u.ingest("b", "failed_login")  # +8
    u.ingest("b", "success_login")  # resets escalation, risk stays 8
    u.ingest("b", "failed_login")  # +8*1 = 8 (not 8*2, escalation reset)
    assert u.score("b") == _pytest.approx(16.0)


def test_unusual_hour_boundary():
    u = ue.Ueba()
    assert u.ingest("c", "unusual_hour", hour=12) == 0.0
    assert u.ingest("c", "unusual_hour", hour=3) == 10.0


def test_bad_event():
    import pytest

    u = ue.Ueba()
    with pytest.raises(ue.UebaError):
        u.ingest("a", "bogus")
    with pytest.raises(ue.UebaError):
        u.ingest("", "new_ip")


def test_stdlib_only():
    assert ue.stdlib_only() is True
