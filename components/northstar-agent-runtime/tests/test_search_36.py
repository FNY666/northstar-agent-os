"""Simulated annealing (mock) tests."""

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


mod = _load("search_36")

def _setup():
    f = lambda x: -(x - 5) ** 2
    nb = lambda x: [n for n in (x - 1, x + 1) if 0 <= n <= 10]
    return f, nb


def test_finds_optimum():
    f, nb = _setup()
    assert mod.simulated_annealing(f, 0, nb, seed=1) == 5


def test_deterministic():
    f, nb = _setup()
    a = mod.simulated_annealing(f, 3, nb, seed=42)
    b = mod.simulated_annealing(f, 3, nb, seed=42)
    assert a == b


def test_in_domain():
    f, nb = _setup()
    assert 0 <= mod.simulated_annealing(f, 7, nb, seed=3) <= 10


def test_none_args():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.simulated_annealing(None, 0, lambda x: [])
