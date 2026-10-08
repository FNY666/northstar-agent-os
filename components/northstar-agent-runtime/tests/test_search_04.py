"""Interpolation search tests."""

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


mod = _load("search_04")

def test_uniform_found():
    data = list(range(0, 200, 2))
    assert mod.interpolation_search(data, 100) == 50


def test_missing():
    data = list(range(0, 200, 2))
    assert mod.interpolation_search(data, 101) == -1


def test_duplicates():
    assert mod.interpolation_search([5, 5, 5, 5], 5) in (0, 1, 2, 3)


def test_empty():
    assert mod.interpolation_search([], 1) == -1
