"""DFS graph search tests."""

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


mod = _load("search_17")

def test_finds_path():
    g = {"a": ["b"], "b": ["c"], "c": []}
    assert mod.dfs_path(g, "a", "c") == ["a", "b", "c"]


def test_no_path():
    g = {"a": ["b"], "b": [], "c": []}
    assert mod.dfs_path(g, "a", "c") is None


def test_cycle_safe():
    g = {"a": ["b"], "b": ["a"]}
    assert mod.dfs_path(g, "a", "c") is None


def test_start_is_goal():
    assert mod.dfs_path({"a": []}, "a", "a") == ["a"]
