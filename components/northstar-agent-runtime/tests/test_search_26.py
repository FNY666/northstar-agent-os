"""A* grid search tests."""

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


mod = _load("search_26")

def test_optimal_length():
    g = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
    p = mod.a_star_grid(g, (0, 0), (2, 2))
    assert len(p) == 5


def test_blocked():
    g = [[0, 1], [1, 0]]
    assert mod.a_star_grid(g, (0, 0), (1, 1)) is None


def test_around_obstacle():
    g = [[0, 0, 0], [1, 1, 0], [0, 0, 0]]
    p = mod.a_star_grid(g, (0, 0), (2, 0))
    assert p is not None and len(p) == 7


def test_same_cell():
    assert mod.a_star_grid([[0]], (0, 0), (0, 0)) == [(0, 0)]
