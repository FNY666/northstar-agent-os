"""Tests for multi_attack_14 (bait-and-switch)."""
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


m = _load("multi_attack_14")


def _drift(a, b):
    ta, tb = set(a.lower().split()), set(b.lower().split())
    if not ta and not tb:
        return 0.0
    return 1.0 - len(ta & tb) / max(len(ta | tb), 1)


def test_switches_caught():
    summary = m.run_all(m.CASES, _drift)
    by_id = {r["case_id"]: r for r in summary["results"]}
    assert by_id["bas-001"]["stopped"] is True
    assert by_id["bas-002"]["stopped"] is True
    assert by_id["bas-003"]["stopped"] is False  # control


def test_scorer_exception_fail_closed():
    def bad(a, b):
        raise RuntimeError("scorer down")

    r = m.run_case(m.CASES[0], bad)
    assert r["drift"] == 1.0
    assert r["stopped"] is True


def test_drift_clamped():
    r = m.run_case(m.CASES[2], lambda a, b: 5.0)
    assert r["drift"] == 1.0


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.MULTI_ATTACK_14_VERSION == "multi-attack-14.v1"
    assert m.SCHEMA_PIN == "northstar.multi-attack-14.v1"
