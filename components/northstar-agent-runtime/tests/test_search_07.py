"""Fibonacci search tests."""

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


mod = _load("search_07")

def test_found():
    assert mod.fibonacci_search([10, 20, 30, 40, 50], 30) == 2


def test_last():
    assert mod.fibonacci_search([10, 20, 30, 40, 50], 50) == 4


def test_missing():
    assert mod.fibonacci_search([10, 20, 30, 40, 50], 35) == -1


def test_empty():
    assert mod.fibonacci_search([], 1) == -1
