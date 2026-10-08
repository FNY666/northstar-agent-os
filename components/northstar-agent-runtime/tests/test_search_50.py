"""Bidirectional Dijkstra tests."""

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


mod = _load("search_50")

def test_matches_dijkstra():
    g = {"a": [("b", 1), ("c", 4)], "b": [("c", 2)], "c": []}
    assert mod.bidirectional_dijkstra(g, "a", "c") == 3


def test_unreachable():
    assert mod.bidirectional_dijkstra({"a": [("b", 1)], "b": []}, "a", "z") is None


def test_start_is_goal():
    assert mod.bidirectional_dijkstra({"a": []}, "a", "a") == 0


def test_none_graph():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.bidirectional_dijkstra(None, "a", "b")
