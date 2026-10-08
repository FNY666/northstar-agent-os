"""Tests for multi_attack_05."""
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


ma = _load("multi_attack_05")


def test_chain_depth():
    assert ma.chain_depth(ma.CHAIN_SCRIPT) == 4
    assert ma.chain_depth(ma.CHAIN_SCRIPT[:1]) == 0


def test_score_capped():
    assert ma.score_trajectory(ma.CHAIN_SCRIPT) == 1.0
    assert ma.score_trajectory(ma.CHAIN_SCRIPT[:3]) == 0.5


def test_run_stops_on_depth():
    r = ma.run_attack(ma.CHAIN_SCRIPT, lambda t: False, depth_threshold=3)
    assert r["stopped"] is True
    assert r["chain_depth"] == 4


def test_shallow_passes():
    r = ma.run_attack(ma.CHAIN_SCRIPT[:2], lambda t: False)
    assert r["stopped"] is False


def test_scorer_fail_closed():
    def bad(p):
        raise RuntimeError("oops")

    assert ma.score_trajectory(ma.CHAIN_SCRIPT, bad) == 1.0


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MULTI_ATTACK_05_VERSION == "multi-attack-05.v1"
