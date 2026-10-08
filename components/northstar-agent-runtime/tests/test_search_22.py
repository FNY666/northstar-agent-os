"""Depth-limited search tests."""

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


mod = _load("search_22")

def test_within_limit():
    g = {"a": ["b"], "b": ["c"], "c": []}
    assert mod.depth_limited_search(g, "a", "b", 1) == ["a", "b"]


def test_beyond_limit():
    g = {"a": ["b"], "b": ["c"], "c": []}
    assert mod.depth_limited_search(g, "a", "c", 1) is None


def test_zero_limit_self():
    assert mod.depth_limited_search({"a": []}, "a", "a", 0) == ["a"]


def test_negative_limit():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.depth_limited_search({"a": []}, "a", "a", -1)
