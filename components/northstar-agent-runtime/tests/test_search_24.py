"""Bellman-Ford tests."""

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


mod = _load("search_24")

def test_negative_edge():
    g = {"a": [("b", -2)], "b": [("c", 3)], "c": []}
    assert mod.bellman_ford(g, "a")["c"] == 1


def test_negative_cycle():
    import pytest
    g = {"a": [("b", 1)], "b": [("a", -2)]}
    with pytest.raises(mod.SearchError):
        mod.bellman_ford(g, "a")


def test_unreachable():
    import math
    g = {"a": [("b", 1)], "b": [], "c": []}
    assert mod.bellman_ford(g, "a")["c"] == math.inf


def test_matches_dijkstra_case():
    g = {"a": [("b", 1), ("c", 4)], "b": [("c", 2)], "c": []}
    d = mod.bellman_ford(g, "a")
    assert d["c"] == 3
