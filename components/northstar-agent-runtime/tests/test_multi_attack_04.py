"""Tests for multi_attack_04."""
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


ma = _load("multi_attack_04")


def test_build_script():
    s = ma.build_script(5)
    assert len(s) == 6
    assert sum(t.is_payload for t in s) == 1
    assert s[-1].is_payload


def test_rejects_negative():
    try:
        ma.build_script(-1)
    except ma.MultiAttack04Error:
        return
    raise AssertionError("should raise")


def test_ratio():
    assert ma.accumulation_ratio(ma.build_script(8)) == 8 / 9
    assert ma.accumulation_ratio(ma.build_script(0)) == 0.0


def test_high_ratio_stops():
    r = ma.run_attack(ma.build_script(8), lambda t: False)
    assert r["stopped"] is True


def test_low_ratio_passes():
    r = ma.run_attack(ma.build_script(1), lambda t: False,
                      ratio_threshold=0.9)
    assert r["stopped"] is False


def test_scorer_fail_closed():
    def bad(p):
        raise RuntimeError("oops")

    assert ma.score_trajectory(ma.build_script(3), bad) == 1.0


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MULTI_ATTACK_04_VERSION == "multi-attack-04.v1"
