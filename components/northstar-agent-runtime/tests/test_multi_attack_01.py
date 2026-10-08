"""Tests for multi_attack_01."""
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


ma = _load("multi_attack_01")


def test_two_variants_five_turns():
    assert len(ma.SCRIPTS) == 2
    for s in ma.SCRIPTS:
        assert len(s.turns) == 5


def test_weights_ascending():
    for s in ma.SCRIPTS:
        ws = [t.weight for t in s.turns]
        assert ws == sorted(ws)
        assert ws[0] < 0.1 and ws[-1] > 0.9


def test_trajectory_mean_weight():
    score = ma.score_trajectory(ma.SCRIPTS[0].turns)
    assert abs(score - 0.45) < 0.01


def test_scorer_fail_closed():
    def bad(prompts):
        raise RuntimeError("oops")

    assert ma.score_trajectory(ma.SCRIPTS[0].turns, bad) == 1.0


def test_run_attack_stopped():
    result = ma.run_attack(ma.SCRIPTS[1], lambda p: "rm -rf" in p)
    assert result["stopped"] is True
    assert result["blocked_turn"] == 5


def test_stdlib_only():
    assert ma.stdlib_only() is True


def test_version_pin():
    assert ma.MULTI_ATTACK_01_VERSION == "multi-attack-01.v1"
