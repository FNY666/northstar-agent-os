"""Best-first search tests."""

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


mod = _load("search_27")

def test_finds_goal():
    g = {"s": ["a", "b"], "a": ["g"], "b": ["g"], "g": []}
    h = lambda n: {"s": 3, "a": 1, "b": 2, "g": 0}[n]
    p = mod.best_first_search(g, "s", "g", h)
    assert p[0] == "s" and p[-1] == "g"


def test_no_path():
    g = {"a": ["b"], "b": []}
    assert mod.best_first_search(g, "a", "z", lambda n: 0) is None


def test_start_is_goal():
    assert mod.best_first_search({"a": []}, "a", "a", lambda n: 0) == ["a"]


def test_none_args():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.best_first_search(None, "a", "b", lambda n: 0)
