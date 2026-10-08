"""Rotated binary search tests."""

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


mod = _load("search_09")

def test_rotated_found():
    assert mod.rotated_binary_search([4, 5, 6, 7, 0, 1, 2], 6) == 2


def test_rotated_missing():
    assert mod.rotated_binary_search([4, 5, 6, 7, 0, 1, 2], 8) == -1


def test_not_rotated():
    assert mod.rotated_binary_search([1, 2, 3, 4], 3) == 2


def test_empty():
    assert mod.rotated_binary_search([], 1) == -1
