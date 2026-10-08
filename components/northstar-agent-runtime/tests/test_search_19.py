"""DFS region size tests."""

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


mod = _load("search_19")

def test_region():
    g = [[0, 0], [0, 0]]
    assert mod.dfs_region_size(g, (0, 0)) == 4


def test_isolated():
    g = [[0, 1], [1, 1]]
    assert mod.dfs_region_size(g, (0, 0)) == 1


def test_blocked_start():
    g = [[1, 0], [0, 0]]
    assert mod.dfs_region_size(g, (0, 0)) == 0


def test_out_of_bounds():
    assert mod.dfs_region_size([[0]], (5, 5)) == 0
