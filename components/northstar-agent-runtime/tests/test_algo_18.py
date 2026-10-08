"""Tests for algo_18 (iterative depth-first search)."""

import importlib.util
import sys
from pathlib import Path

MOD = Path(__file__).resolve().parent.parent / "algo_18.py"


def _load():
    spec = importlib.util.spec_from_file_location("algo_18", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algo_18"] = module
    spec.loader.exec_module(module)
    return module


m = _load()

GRAPH = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}


def test_version_and_stdlib_only():
    assert m.ALGO_18_VERSION == "algo-18.v1"
    m.stdlib_only()


def test_dfs_visit_order():
    # leftmost neighbor visited first (neighbors pushed in reverse)
    assert m.dfs(GRAPH, "a") == ["a", "b", "d", "c"]


def test_disconnected_graph_only_reaches_component():
    g = {"a": ["b"], "b": [], "x": ["y"], "y": []}
    assert m.dfs(g, "a") == ["a", "b"]
    assert m.dfs(g, "x") == ["x", "y"]


def test_single_node_and_missing_start():
    assert m.dfs({"solo": []}, "solo") == ["solo"]
    assert m.dfs(GRAPH, "zzz") == []
    assert m.dfs({}, "a") == []


def test_cycle_terminates():
    g = {"a": ["b"], "b": ["c"], "c": ["a"]}
    assert m.dfs(g, "a") == ["a", "b", "c"]
