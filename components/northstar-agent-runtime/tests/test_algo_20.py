"""Tests for algo_20 (A* shortest-path search)."""

import importlib.util
import sys
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "algo_20.py"


def _load():
    spec = importlib.util.spec_from_file_location("algo_20", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algo_20"] = module
    spec.loader.exec_module(module)
    return module


m = _load()

GRAPH = {"s": {"a": 4, "b": 2}, "a": {"t": 1}, "b": {"a": 1, "t": 5}, "t": {}}
H = {"s": 3, "a": 2, "b": 2, "t": 0}.__getitem__


def test_version_and_stdlib_only():
    assert m.ALGO_20_VERSION == "algo-20.v1"
    m.stdlib_only()


def test_shortest_path():
    assert m.a_star(GRAPH, "s", "t", H) == ["s", "b", "a", "t"]


def test_start_is_goal():
    assert m.a_star(GRAPH, "s", "s", H) == ["s"]
    assert m.a_star(GRAPH, "t", "t", H) == ["t"]


def test_unreachable_goal_returns_none():
    g = {"s": {"a": 1}, "a": {}, "z": {}}
    assert m.a_star(g, "s", "z", lambda n: 0) is None


def test_disconnected_graph_returns_none_across_components():
    g = {"a": {"b": 1}, "b": {}, "x": {"y": 1}, "y": {}}
    assert m.a_star(g, "a", "y", lambda n: 0) is None


def test_negative_weight_raises():
    with pytest.raises(ValueError):
        m.a_star({"s": {"a": -2}, "a": {}}, "s", "a", lambda n: 0)


def test_zero_heuristic_degrades_to_dijkstra():
    assert m.a_star(GRAPH, "s", "t", lambda n: 0) == ["s", "b", "a", "t"]
