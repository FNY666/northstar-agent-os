"""Iterative deepening DFS tests."""

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


mod = _load("search_21")

def test_found():
    g = {"a": ["b"], "b": ["c"], "c": []}
    assert mod.iddfs(g, "a", "c", 5) == ["a", "b", "c"]


def test_depth_too_shallow():
    g = {"a": ["b"], "b": ["c"], "c": []}
    assert mod.iddfs(g, "a", "c", 1) is None


def test_no_path():
    g = {"a": ["b"], "b": []}
    assert mod.iddfs(g, "a", "z", 5) is None


def test_negative_depth():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.iddfs({"a": []}, "a", "a", -1)
