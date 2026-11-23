"""Tests for multi_attack_06."""
import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


ma = _load("multi_attack_06")


def test_authority_ascending():
    levels = [t.authority for t in ma.AUTHORITY_SCRIPT]
    assert levels == sorted(levels)
    assert levels[-1] == ma.Authority.EMERGENCY_OVERRIDE


def test_max_authority():
    assert ma.max_authority(ma.AUTHORITY_SCRIPT) == ma.Authority.EMERGENCY_OVERRIDE
    assert ma.max_authority(ma.AUTHORITY_SCRIPT[:1]) == ma.Authority.PEER


def test_score():
    assert ma.score_trajectory(ma.AUTHORITY_SCRIPT) == 1.0
    assert ma.score_trajectory(ma.AUTHORITY_SCRIPT[:2]) == 0.5


def test_run_stops_at_admin():
    r = ma.run_attack(ma.AUTHORITY_SCRIPT, lambda t: False)
    assert r["stopped"] is True
    assert r["max_authority"] == "EMERGENCY_OVERRIDE"


def test_low_authority_passes():
    r = ma.run_attack(ma.AUTHORITY_SCRIPT[:1], lambda t: False)
    assert r["stopped"] is False


def test_scorer_fail_closed():
    def bad(p):
        raise RuntimeError("oops")

    assert ma.score_trajectory(ma.AUTHORITY_SCRIPT, bad) == 1.0


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MULTI_ATTACK_06_VERSION == "multi-attack-06.v1"
