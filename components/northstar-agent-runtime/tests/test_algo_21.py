"""algo_21 (topological sort) tests."""

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


m = _load("algo_21")


def test_known_answer():
    g = {"A": ["B", "C"], "B": ["D"], "C": ["D"], "D": []}
    assert m.topological_sort(g) == ["A", "B", "C", "D"]


def test_ordering_valid():
    g = {"shop": ["cook"], "shop2": ["cook"], "cook": ["eat"], "eat": []}
    order = m.topological_sort(g)
    assert set(order) == {"shop", "shop2", "cook", "eat"}
    assert order.index("cook") > order.index("shop")
    assert order.index("cook") > order.index("shop2")
    assert order.index("eat") > order.index("cook")


def test_empty_and_single_node():
    assert m.topological_sort({}) == []
    assert m.topological_sort({"solo": []}) == ["solo"]


def test_disconnected_components():
    order = m.topological_sort({"A": ["B"], "B": [], "C": [], "D": ["C"]})
    assert set(order) == {"A", "B", "C", "D"}
    assert order.index("A") < order.index("B")
    assert order.index("D") < order.index("C")


def test_cycle_raises():
    try:
        m.topological_sort({"A": ["B"], "B": ["C"], "C": ["A"]})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_self_loop_raises():
    try:
        m.topological_sort({"A": ["A"]})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_stdlib_only():
    assert m.stdlib_only() is True
