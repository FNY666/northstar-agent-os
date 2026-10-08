"""Topological sort tests."""

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


mod = _load("search_47")

def _valid(g, order):
    pos = {n: i for i, n in enumerate(order)}
    return all(pos[u] < pos[v] for u in g for v in g[u])


def test_order():
    g = {"a": ["b"], "b": ["c"], "c": []}
    assert _valid(g, mod.topological_sort(g))


def test_cycle_raises():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.topological_sort({"a": ["b"], "b": ["a"]})


def test_single():
    assert mod.topological_sort({"a": []}) == ["a"]


def test_none():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.topological_sort(None)
