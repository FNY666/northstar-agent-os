"""Random-restart hill climbing tests."""

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


mod = _load("search_35")

def _setup():
    f = lambda x: max(3 - abs(x - 2), 5 - abs(x - 8))
    nb = lambda x: [n for n in (x - 1, x + 1) if 0 <= n <= 10]
    return f, nb


def test_beats_single_restart():
    f, nb = _setup()
    assert mod.random_restart_hill_climbing(f, [0, 9], nb) == 8


def test_single_start_local():
    f, nb = _setup()
    assert mod.random_restart_hill_climbing(f, [0], nb) == 2


def test_deterministic():
    f, nb = _setup()
    a = mod.random_restart_hill_climbing(f, [0, 4, 9], nb, seed=7)
    b = mod.random_restart_hill_climbing(f, [0, 4, 9], nb, seed=7)
    assert a == b


def test_none_args():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.random_restart_hill_climbing(None, [0], lambda x: [])
