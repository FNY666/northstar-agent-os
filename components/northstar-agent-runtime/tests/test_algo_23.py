"""algo_23 (Prim MST) tests."""

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


m = _load("algo_23")

GRAPH = {
    0: {1: 10, 2: 6, 3: 5},
    1: {0: 10, 3: 15},
    2: {0: 6, 3: 4},
    3: {0: 5, 1: 15, 2: 4},
}

EXPECTED = {
    (frozenset((0, 3)), 5),
    (frozenset((2, 3)), 4),
    (frozenset((0, 1)), 10),
}


def _norm(edges):
    return {(frozenset((u, v)), w) for u, v, w in edges}


def test_known_answer():
    mst, total = m.prim(GRAPH, 0)
    assert total == 19
    assert _norm(mst) == EXPECTED


def test_start_independent_of_root():
    for start in (1, 2, 3):
        mst, total = m.prim(GRAPH, start)
        assert total == 19, start
        assert _norm(mst) == EXPECTED, start


def test_single_node():
    assert m.prim({"A": {}}, "A") == ([], 0)


def test_disconnected_component_only():
    mst, total = m.prim({0: {1: 7}, 1: {0: 7}, 9: {}}, 0)
    assert total == 7
    assert _norm(mst) == {(frozenset((0, 1)), 7)}


def test_line_graph():
    g = {0: {1: 2}, 1: {0: 2, 2: 3}, 2: {1: 3}}
    mst, total = m.prim(g, 0)
    assert total == 5
    assert len(mst) == 2


def test_stdlib_only():
    assert m.stdlib_only() is True
