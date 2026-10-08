"""BFS grid shortest path tests."""

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


mod = _load("search_18")

def test_open_grid():
    g = [[0, 0], [0, 0]]
    assert mod.bfs_grid_shortest(g, (0, 0), (1, 1)) == 2


def test_blocked():
    g = [[0, 1], [1, 0]]
    assert mod.bfs_grid_shortest(g, (0, 0), (1, 1)) is None


def test_start_blocked():
    g = [[1, 0], [0, 0]]
    assert mod.bfs_grid_shortest(g, (0, 0), (1, 1)) is None


def test_same_cell():
    g = [[0]]
    assert mod.bfs_grid_shortest(g, (0, 0), (0, 0)) == 0
