"""Tests for multi_attack_03."""
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


ma = _load("multi_attack_03")


def test_script_descends():
    ss = [t.strictness for t in ma.PERSONA_SCRIPT]
    assert ss == sorted(ss, reverse=True)
    assert ss[0] == 1.0 and ss[-1] < 0.1


def test_drift_small_early():
    assert ma.cumulative_drift(ma.PERSONA_SCRIPT[:2]) < 0.2


def test_drift_large_full():
    assert ma.cumulative_drift(ma.PERSONA_SCRIPT) > 0.9


def test_run_stops_on_drift():
    r = ma.run_attack(ma.PERSONA_SCRIPT, lambda t: False)
    assert r["stopped"] is True  # drift 0.95 >= 0.5


def test_scorer_fail_closed():
    def bad(p):
        raise RuntimeError("oops")

    assert ma.score_trajectory(ma.PERSONA_SCRIPT, bad) == 1.0


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MULTI_ATTACK_03_VERSION == "multi-attack-03.v1"
