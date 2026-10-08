"""A* graph search tests."""

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


mod = _load("search_49")

def _setup():
    g = {"s": [("a", 1), ("b", 4)], "a": [("g", 5)], "b": [("g", 1)], "g": []}
    h = {"s": 3, "a": 2, "b": 1, "g": 0}.__getitem__
    return g, h


def test_optimal():
    g, h = _setup()
    p, c = mod.a_star_graph(g, "s", "g", h)
    assert p == ["s", "b", "g"] and c == 5


def test_unreachable():
    import math
    g, h = _setup()
    p, c = mod.a_star_graph(g, "s", "z", h)
    assert p is None and c == math.inf


def test_start_is_goal():
    g, h = _setup()
    p, c = mod.a_star_graph(g, "s", "s", h)
    assert p == ["s"] and c == 0


def test_none_args():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.a_star_graph(None, "s", "g", lambda n: 0)
