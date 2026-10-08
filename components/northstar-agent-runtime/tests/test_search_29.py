"""Uniform-cost search tests."""

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


mod = _load("search_29")

def test_cheapest():
    g = {"a": [("b", 5), ("c", 1)], "b": [("d", 1)], "c": [("d", 1)], "d": []}
    p, c = mod.uniform_cost_search(g, "a", "d")
    assert p == ["a", "c", "d"] and c == 2


def test_unreachable():
    import math
    g = {"a": [("b", 1)], "b": []}
    p, c = mod.uniform_cost_search(g, "a", "z")
    assert p is None and c == math.inf


def test_start_is_goal():
    p, c = mod.uniform_cost_search({"a": []}, "a", "a")
    assert p == ["a"] and c == 0


def test_none_graph():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.uniform_cost_search(None, "a", "b")
