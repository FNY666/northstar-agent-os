"""Tests for multi_attack_10."""
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


ma = _load("multi_attack_10")


def test_ladder_ascending():
    sizes = [t.request_size for t in ma.LADDER_SCRIPT]
    assert sizes == sorted(sizes)
    assert sizes[-1] == 1.0


def test_slope():
    assert abs(ma.commitment_slope(ma.LADDER_SCRIPT) - 0.225) < 0.001


def test_slope_single_turn():
    assert ma.commitment_slope(ma.LADDER_SCRIPT[:1]) == 0.0


def test_run_stops():
    r = ma.run_attack(ma.LADDER_SCRIPT, lambda t: False)
    assert r["stopped"] is True  # score 0.45 >= 0.4


def test_flat_passes():
    flat = [ma.Turn(1, "a", 0.1), ma.Turn(2, "b", 0.1)]
    r = ma.run_attack(flat, lambda t: False)
    assert r["stopped"] is False


def test_scorer_fail_closed():
    def bad(p):
        raise RuntimeError("oops")

    assert ma.score_trajectory(ma.LADDER_SCRIPT, bad) == 1.0


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MULTI_ATTACK_10_VERSION == "multi-attack-10.v1"
