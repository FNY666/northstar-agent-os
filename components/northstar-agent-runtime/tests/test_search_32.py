"""SMA* (simplified mock) tests."""

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


mod = _load("search_32")

def test_finds_goal():
    g = {"s": ["a"], "a": ["g"], "g": []}
    h = lambda n: {"s": 2, "a": 1, "g": 0}[n]
    assert mod.sma_star(g, "s", "g", h) == ["s", "a", "g"]


def test_tight_cap_still_works():
    g = {"s": ["a"], "a": ["g"], "g": []}
    h = lambda n: {"s": 2, "a": 1, "g": 0}[n]
    p = mod.sma_star(g, "s", "g", h, max_nodes=2)
    assert p == ["s", "a", "g"]


def test_bad_cap():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.sma_star({"a": []}, "a", "a", lambda n: 0, max_nodes=0)


def test_start_is_goal():
    assert mod.sma_star({"a": []}, "a", "a", lambda n: 0) == ["a"]
