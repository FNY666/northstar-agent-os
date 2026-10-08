"""algo_22 (Kruskal MST) tests."""

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


m = _load("algo_22")


def test_known_answer():
    edges = [(0, 1, 10), (0, 2, 6), (0, 3, 5), (1, 3, 15), (2, 3, 4)]
    mst, total = m.kruskal([0, 1, 2, 3], edges)
    assert total == 19
    assert mst == [(2, 3, 4), (0, 3, 5), (0, 1, 10)]


def test_mst_spans_all_nodes():
    nodes = [1, 2, 3, 4, 5]
    edges = [(1, 2, 1), (2, 3, 2), (3, 4, 3), (4, 5, 4), (1, 5, 10), (2, 4, 8)]
    mst, total = m.kruskal(nodes, edges)
    assert total == 10
    assert len(mst) == 4
    touched = {u for u, v, _ in mst} | {v for u, v, _ in mst}
    assert touched == set(nodes)


def test_empty_and_single_node():
    assert m.kruskal([], []) == ([], 0)
    assert m.kruskal(["A"], []) == ([], 0)


def test_disconnected_gives_forest():
    mst, total = m.kruskal([1, 2, 3, 4], [(1, 2, 1), (3, 4, 2)])
    assert total == 3
    assert len(mst) == 2


def test_cycle_edges_skipped():
    mst, total = m.kruskal([1, 2, 3], [(1, 2, 1), (2, 3, 1), (1, 3, 100)])
    assert total == 2
    assert len(mst) == 2


def test_stdlib_only():
    assert m.stdlib_only() is True
