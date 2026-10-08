"""Hill climbing tests."""

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


mod = _load("search_34")

def _setup():
    f = lambda x: -(x - 5) ** 2
    nb = lambda x: [n for n in (x - 1, x + 1) if 0 <= n <= 10]
    return f, nb


def test_climb_up():
    f, nb = _setup()
    assert mod.hill_climbing(f, 0, nb) == 5


def test_climb_down():
    f, nb = _setup()
    assert mod.hill_climbing(f, 10, nb) == 5


def test_already_optimal():
    f, nb = _setup()
    assert mod.hill_climbing(f, 5, nb) == 5


def test_none_args():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.hill_climbing(None, 0, lambda x: [])
