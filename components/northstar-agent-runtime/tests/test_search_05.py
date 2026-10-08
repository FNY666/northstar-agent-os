"""Exponential search tests."""

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


mod = _load("search_05")

def test_found():
    assert mod.exponential_search([1, 2, 3, 4, 5], 4) == 3


def test_first():
    assert mod.exponential_search([1, 2, 3, 4, 5], 1) == 0


def test_missing():
    assert mod.exponential_search([1, 2, 3, 4, 5], 9) == -1


def test_empty():
    assert mod.exponential_search([], 1) == -1
