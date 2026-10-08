"""Tests for algo_19 (Dijkstra's shortest-path algorithm)."""

import importlib.util
import sys
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "algo_19.py"


def _load():
    spec = importlib.util.spec_from_file_location("algo_19", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algo_19"] = module
    spec.loader.exec_module(module)
    return module


m = _load()

GRAPH = {"s": {"a": 4, "b": 2}, "a": {"t": 1}, "b": {"a": 1, "t": 5}, "t": {}}


def test_version_and_stdlib_only():
    assert m.ALGO_19_VERSION == "algo-19.v1"
    m.stdlib_only()


def test_shortest_distances():
    assert m.dijkstra(GRAPH, "s") == {"s": 0.0, "a": 3.0, "b": 2.0, "t": 4.0}


def test_disconnected_graph_unreachable_is_inf():
    dist = m.dijkstra({"s": {"a": 1}, "a": {}, "x": {}}, "s")
    assert dist["s"] == 0.0
    assert dist["a"] == 1.0
    assert dist["x"] == float("inf")


def test_negative_weight_raises():
    with pytest.raises(ValueError):
        m.dijkstra({"s": {"a": -1}, "a": {}}, "s")


def test_single_node():
    assert m.dijkstra({"only": {}}, "only") == {"only": 0.0}


def test_zero_weight_edges():
    dist = m.dijkstra({"s": {"a": 0, "b": 3}, "a": {"b": 0}, "b": {}}, "s")
    assert dist == {"s": 0.0, "a": 0.0, "b": 0.0}
