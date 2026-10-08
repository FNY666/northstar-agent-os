"""Tests for multi_attack_02."""
import importlib.util
import math
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


ma = _load("multi_attack_02")


def test_build_attack():
    a = ma.build_attack("x", "prompt", 8)
    assert len(a.shots) == 8
    assert a.attack_prompt == "prompt"


def test_rejects_negative_n():
    try:
        ma.build_attack("x", "p", -1)
    except ma.MultiAttack02Error:
        return
    raise AssertionError("should raise")


def test_risk_monotonic_capped():
    assert ma.shot_risk(0) < ma.shot_risk(4) < ma.shot_risk(64)
    assert ma.shot_risk(10_000) == 1.0


def test_high_shot_stopped_by_risk():
    a = ma.build_attack("x", "innocent", 256)
    r = ma.run_attack(a, lambda p: False)
    assert r["stopped"] is True
    assert r["prompt_blocked"] is False


def test_gate_exception_fail_closed():
    a = ma.build_attack("x", "p", 0)

    def bad(p):
        raise RuntimeError("oops")

    r = ma.run_attack(a, bad)
    assert r["prompt_blocked"] is True
    assert r["stopped"] is True


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MULTI_ATTACK_02_VERSION == "multi-attack-02.v1"
