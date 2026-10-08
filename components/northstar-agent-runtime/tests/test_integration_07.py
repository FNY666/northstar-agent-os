"""Integration 07 tests."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


it = _load("interleaved_thinking")
gc = _load("goal_comparator")
i07 = _load("integration_07")


def test_step_runs_and_not_done():
    comp = gc.GoalComparator("count", max_cycles=10)
    r = i07.TerminatingRunner(lambda t, a: "ok", comp)
    out = r.run("need to call", "tool", {"x": 1}, {"count": 1}, ["t1"])
    assert out["result"] == "ok"
    assert out["done"] is False
    assert out["cycles"] == 1


def test_step_done_on_empty_queue():
    comp = gc.GoalComparator("x")
    r = i07.TerminatingRunner(lambda t, a: "ok", comp)
    out = r.run("r", "tool", {}, {}, task_queue=[])
    assert out["done"] is True


def test_step_done_on_max_cycles():
    comp = gc.GoalComparator("never", max_cycles=1)
    r = i07.TerminatingRunner(lambda t, a: "ok", comp)
    r.run("r", "tool", {}, {}, ["t1"])
    out = r.run("r", "tool", {}, {}, ["t1"])
    assert out["done"] is True


def test_missing_reasoning_raises():
    comp = gc.GoalComparator("x")
    r = i07.TerminatingRunner(lambda t, a: "ok", comp)
    with pytest.raises(it.InterleavedError):
        r.run("", "tool", {}, {})


def test_version_pin():
    assert i07.INTEGRATION_07_VERSION == "integration-07.v1"
    assert i07.stdlib_only() is True
