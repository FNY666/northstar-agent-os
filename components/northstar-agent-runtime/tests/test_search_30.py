"""IDA* (simplified mock) tests."""

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


mod = _load("search_30")

def test_finds_path():
    g = [[0, 0], [0, 0]]
    p = mod.ida_star(g, (0, 0), (1, 1))
    assert p is not None and p[0] == (0, 0) and p[-1] == (1, 1)


def test_optimal_length():
    g = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
    assert len(mod.ida_star(g, (0, 0), (2, 2))) == 5


def test_blocked():
    g = [[0, 1], [1, 0]]
    assert mod.ida_star(g, (0, 0), (1, 1)) is None


def test_same_cell():
    assert mod.ida_star([[0]], (0, 0), (0, 0)) == [(0, 0)]
