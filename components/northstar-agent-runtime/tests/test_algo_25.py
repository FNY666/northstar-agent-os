"""algo_25 (Floyd-Warshall) tests."""

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


m = _load("algo_25")

INF = float("inf")


def test_known_answer():
    nodes = [0, 1, 2, 3]
    edges = [(0, 1, 4), (0, 2, 1), (2, 1, 2), (1, 3, 1), (2, 3, 5)]
    d = m.floyd_warshall(nodes, edges)
    assert d[0][1] == 3   # 0 -> 2 -> 1
    assert d[0][3] == 4   # 0 -> 2 -> 1 -> 3
    assert d[2][3] == 3   # 2 -> 1 -> 3
    assert d[1][3] == 1
    assert d[3][0] == INF  # unreachable


def test_diagonal_zero():
    d = m.floyd_warshall(["a", "b"], [])
    assert d["a"]["a"] == 0 and d["b"]["b"] == 0
    assert d["a"]["b"] == INF


def test_empty_and_single_node():
    assert m.floyd_warshall([], []) == {}
    assert m.floyd_warshall(["A"], []) == {"A": {"A": 0}}


def test_disconnected():
    d = m.floyd_warshall(["A", "B", "C"], [("A", "B", 1)])
    assert d["A"]["B"] == 1
    assert d["B"]["A"] == INF
    assert d["A"]["C"] == INF


def test_parallel_edges_keep_minimum():
    d = m.floyd_warshall(["A", "B"], [("A", "B", 9), ("A", "B", 2)])
    assert d["A"]["B"] == 2


def test_stdlib_only():
    assert m.stdlib_only() is True
