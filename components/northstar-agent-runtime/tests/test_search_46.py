"""BFS level order tests."""

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


mod = _load("search_46")

def test_order():
    t = {"v": 1, "kids": [{"v": 2, "kids": []}, {"v": 3, "kids": []}]}
    assert mod.level_order(t) == [1, 2, 3]


def test_deep():
    t = {"v": 1, "kids": [{"v": 2, "kids": [{"v": 3, "kids": []}]}]}
    assert mod.level_order(t) == [1, 2, 3]


def test_none():
    assert mod.level_order(None) == []


def test_single():
    assert mod.level_order({"v": 7, "kids": []}) == [7]
