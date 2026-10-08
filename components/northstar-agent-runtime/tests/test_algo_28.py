"""algo_28 (bipartite check) tests."""

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


m = _load("algo_28")


def test_square_is_bipartite():
    g = {"A": ["B", "D"], "B": ["A", "C"], "C": ["B", "D"], "D": ["A", "C"]}
    ok, part = m.is_bipartite(g)
    assert ok is True
    assert part is not None
    a, b = part
    assert a | b == {"A", "B", "C", "D"}
    assert a & b == set()
    assert "A" in a and "C" in a and "B" in b and "D" in b


def test_triangle_not_bipartite():
    ok, part = m.is_bipartite({"A": ["B", "C"], "B": ["A", "C"], "C": ["A", "B"]})
    assert ok is False
    assert part is None


def test_empty_graph():
    ok, part = m.is_bipartite({})
    assert ok is True
    assert part == (set(), set())


def test_single_node():
    ok, part = m.is_bipartite({"A": []})
    assert ok is True
    assert part[0] | part[1] == {"A"}


def test_disconnected_components():
    g = {"A": ["B"], "B": ["A"], "C": ["D"], "D": ["C"]}
    ok, part = m.is_bipartite(g)
    assert ok is True
    assert part[0] | part[1] == {"A", "B", "C", "D"}
    assert part[0] & part[1] == set()


def test_odd_cycle_not_bipartite():
    g = {"A": ["B", "E"], "B": ["A", "C"], "C": ["B", "D"], "D": ["C", "E"], "E": ["D", "A"]}
    ok, part = m.is_bipartite(g)
    assert ok is False
    assert part is None


def test_stdlib_only():
    assert m.stdlib_only() is True
