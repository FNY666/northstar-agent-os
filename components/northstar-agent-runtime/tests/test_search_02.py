"""Binary search tests."""

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


mod = _load("search_02")

def test_found():
    assert mod.binary_search([1, 3, 5, 7, 9], 1) == 0


def test_found_last():
    assert mod.binary_search([1, 3, 5, 7, 9], 9) == 4


def test_missing():
    assert mod.binary_search([1, 3, 5, 7, 9], 6) == -1


def test_empty():
    assert mod.binary_search([], 1) == -1
