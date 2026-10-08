"""Tests for multi_attack_09."""
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


ma = _load("multi_attack_09")


def test_debt_ratio():
    assert ma.debt_ratio(ma.RECIPROCITY_SCRIPT) == 1.0
    assert ma.debt_ratio(ma.RECIPROCITY_SCRIPT[:2]) == 0.0


def test_run_stops():
    r = ma.run_attack(ma.RECIPROCITY_SCRIPT, lambda t: False)
    assert r["stopped"] is True
    assert r["debt_ratio"] == 1.0


def test_no_ask_passes():
    r = ma.run_attack(ma.RECIPROCITY_SCRIPT[:3], lambda t: False)
    assert r["stopped"] is False


def test_scorer_fail_closed():
    def bad(p):
        raise RuntimeError("oops")

    assert ma.score_trajectory(ma.RECIPROCITY_SCRIPT, bad) == 1.0


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MULTI_ATTACK_09_VERSION == "multi-attack-09.v1"
