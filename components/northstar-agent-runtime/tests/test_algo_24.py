"""algo_24 (Bellman-Ford) tests."""

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


m = _load("algo_24")


def test_known_answer():
    g = {"S": {"A": 4, "B": 2}, "A": {"T": 3}, "B": {"A": 1, "T": 5}, "T": {}}
    assert m.bellman_ford(g, "S") == {"S": 0, "A": 3, "B": 2, "T": 6}


def test_negative_edge_no_cycle():
    d = m.bellman_ford({"A": {"B": -2}, "B": {"C": 1}, "C": {}}, "A")
    assert d == {"A": 0, "B": -2, "C": -1}


def test_unreachable_is_inf():
    d = m.bellman_ford({"A": {}, "B": {}}, "A")
    assert d["A"] == 0
    assert d["B"] == float("inf")


def test_single_node():
    assert m.bellman_ford({"X": {}}, "X") == {"X": 0}


def test_negative_cycle_raises():
    try:
        m.bellman_ford({"A": {"B": -1}, "B": {"A": -1}}, "A")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_self_negative_loop_raises():
    try:
        m.bellman_ford({"A": {"A": -5}}, "A")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_stdlib_only():
    assert m.stdlib_only() is True
