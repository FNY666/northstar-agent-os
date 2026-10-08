"""Tests for algo_17 (breadth-first search)."""

import importlib.util
import sys
from pathlib import Path

MOD = Path(__file__).resolve().parent.parent / "algo_17.py"


def _load():
    spec = importlib.util.spec_from_file_location("algo_17", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algo_17"] = module
    spec.loader.exec_module(module)
    return module


m = _load()

GRAPH = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}


def test_version_and_stdlib_only():
    assert m.ALGO_17_VERSION == "algo-17.v1"
    m.stdlib_only()


def test_bfs_visit_order():
    assert m.bfs(GRAPH, "a") == ["a", "b", "c", "d"]


def test_disconnected_graph_only_reaches_component():
    g = {"a": ["b"], "b": [], "x": ["y"], "y": []}
    assert m.bfs(g, "a") == ["a", "b"]
    assert m.bfs(g, "x") == ["x", "y"]


def test_single_node_and_missing_start():
    assert m.bfs({"solo": []}, "solo") == ["solo"]
    assert m.bfs(GRAPH, "zzz") == []
    assert m.bfs({}, "a") == []


def test_cycle_terminates():
    g = {"a": ["b"], "b": ["c"], "c": ["a"]}
    assert m.bfs(g, "a") == ["a", "b", "c"]
