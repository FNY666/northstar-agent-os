"""Greedy best-first search tests."""

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


mod = _load("search_28")

def test_picks_heuristic_best():
    g = {"s": ["a", "b"], "a": ["g"], "b": ["g"], "g": []}
    h = lambda n: {"s": 3, "a": 1, "b": 5, "g": 0}[n]
    assert mod.greedy_best_first(g, "s", "g", h) == ["s", "a", "g"]


def test_no_path():
    g = {"a": ["b"], "b": []}
    assert mod.greedy_best_first(g, "a", "z", lambda n: 0) is None


def test_start_is_goal():
    assert mod.greedy_best_first({"a": []}, "a", "a", lambda n: 0) == ["a"]


def test_iter_cap():
    g = {"a": ["b"], "b": ["a"]}
    assert mod.greedy_best_first(g, "a", "z", lambda n: 0, max_iters=10) is None
