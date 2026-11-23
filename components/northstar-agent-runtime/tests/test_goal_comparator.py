"""Goal comparator tests."""

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


gc = _load("goal_comparator")


def test_empty_queue_done():
    g = gc.GoalComparator("obj")
    r = g.check({}, task_queue=[])
    assert r.done is True


def test_comparator_fn():
    g = gc.GoalComparator(
        "obj", comparator_fn=lambda o, s: s.get("x") == 1
    )
    assert g.check({"x": 0}).done is False
    assert g.check({"x": 1}).done is True


def test_max_cycles():
    g = gc.GoalComparator("obj", max_cycles=2)
    g.check({})
    g.check({})
    r = g.check({})
    assert r.done is True


def test_rejects_empty_objective():
    with pytest.raises(gc.GoalComparatorError):
        gc.GoalComparator("")


def test_stdlib_only():
    assert gc.stdlib_only() is True


def test_version_pin():
    assert gc.GOAL_COMPARATOR_VERSION == "goal-comparator.v1"
