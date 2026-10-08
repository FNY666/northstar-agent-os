"""RBFS (simplified mock) tests."""

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


mod = _load("search_31")

def test_finds_goal():
    g = {"s": ["a"], "a": ["g"], "g": []}
    h = lambda n: {"s": 2, "a": 1, "g": 0}[n]
    assert mod.rbfs_search(g, "s", "g", h) == ["s", "a", "g"]


def test_no_path():
    g = {"a": ["b"], "b": []}
    assert mod.rbfs_search(g, "a", "z", lambda n: 0) is None


def test_start_is_goal():
    assert mod.rbfs_search({"a": []}, "a", "a", lambda n: 0) == ["a"]


def test_none_args():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.rbfs_search(None, "a", "b", lambda n: 0)
