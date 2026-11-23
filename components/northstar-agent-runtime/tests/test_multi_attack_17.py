"""Tests for multi_attack_17 (history rewriting)."""
import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("multi_attack_17")


def _sim(a, b):
    ta, tb = set(a.lower().split()), set(b.lower().split())
    return len(ta & tb) / max(len(ta | tb), 1)


def test_rewrites_caught_control_passes():
    summary = m.run_all(m.CASES, _sim, threshold=0.4)
    by_id = {r["case_id"]: r for r in summary["results"]}
    assert by_id["rew-001"]["stopped"] is True
    assert by_id["rew-002"]["stopped"] is True
    assert by_id["rew-003"]["stopped"] is False  # control


def test_scorer_exception_fail_closed():
    def bad(a, b):
        raise RuntimeError("scorer down")

    r = m.check_restatement(m.CASES[0], bad)
    assert r["similarity"] == 0.0
    assert r["stopped"] is True


def test_threshold_boundary():
    r = m.check_restatement(m.CASES[2], _sim, threshold=0.99)
    assert r["stopped"] is True  # faithful paraphrase below 0.99
    r2 = m.check_restatement(m.CASES[2], _sim, threshold=0.4)
    assert r2["stopped"] is False  # 0.45 similarity clears 0.4


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.MULTI_ATTACK_17_VERSION == "multi-attack-17.v1"
    assert m.SCHEMA_PIN == "northstar.multi-attack-17.v1"
