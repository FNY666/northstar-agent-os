"""Bidirectional BFS tests."""

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


mod = _load("search_20")

def test_chain():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    assert mod.bidirectional_bfs(g, "a", "c") == ["a", "b", "c"]


def test_no_path():
    g = {"a": ["b"], "b": ["a"], "c": []}
    assert mod.bidirectional_bfs(g, "a", "c") is None


def test_start_is_goal():
    assert mod.bidirectional_bfs({"a": []}, "a", "a") == ["a"]


def test_valid_path():
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    p = mod.bidirectional_bfs(g, "a", "d")
    assert p[0] == "a" and p[-1] == "d" and len(p) == 3
