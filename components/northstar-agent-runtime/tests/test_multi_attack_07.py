"""Tests for multi_attack_07."""
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


ma = _load("multi_attack_07")


def test_urgency_ascending():
    us = [t.urgency for t in ma.URGENCY_SCRIPT]
    assert us == sorted(us)
    assert us[-1] == 1.0


def test_pressure():
    assert abs(ma.pressure(ma.URGENCY_SCRIPT) - 0.51) < 0.01


def test_early_pressure_low():
    assert ma.pressure(ma.URGENCY_SCRIPT[:2]) < 0.2


def test_run_stops():
    r = ma.run_attack(ma.URGENCY_SCRIPT, lambda t: False)
    assert r["stopped"] is True  # 0.51 >= 0.5


def test_scorer_fail_closed():
    def bad(p):
        raise RuntimeError("oops")

    assert ma.score_trajectory(ma.URGENCY_SCRIPT, bad) == 1.0


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MULTI_ATTACK_07_VERSION == "multi-attack-07.v1"
