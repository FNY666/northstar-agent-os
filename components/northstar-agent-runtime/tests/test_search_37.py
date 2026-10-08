"""Genetic search (mock) tests."""

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


mod = _load("search_37")

def test_max_ones():
    best = mod.genetic_search(sum, [0, 1], 5, seed=0)
    assert sum(best) == 5


def test_length():
    best = mod.genetic_search(sum, [0, 1], 8, seed=1)
    assert len(best) == 8


def test_deterministic():
    a = mod.genetic_search(sum, [0, 1], 5, seed=9)
    b = mod.genetic_search(sum, [0, 1], 5, seed=9)
    assert a == b


def test_none_fitness():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.genetic_search(None, [0, 1], 5)
