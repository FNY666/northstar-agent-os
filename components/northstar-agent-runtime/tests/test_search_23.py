"""Dijkstra shortest path tests."""

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


mod = _load("search_23")

def test_distances():
    g = {"a": [("b", 1)], "b": [("c", 2)], "c": []}
    d = mod.dijkstra(g, "a")
    assert d == {"a": 0, "b": 1, "c": 3}


def test_shorter_indirect():
    g = {"a": [("b", 10), ("c", 1)], "b": [], "c": [("b", 1)]}
    assert mod.dijkstra(g, "a")["b"] == 2


def test_unreachable():
    g = {"a": [("b", 1)], "b": [], "c": []}
    import math
    assert mod.dijkstra(g, "a")["c"] == math.inf


def test_single_node():
    assert mod.dijkstra({"a": []}, "a") == {"a": 0}
