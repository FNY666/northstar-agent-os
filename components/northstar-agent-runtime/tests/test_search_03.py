"""Jump search tests."""

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


mod = _load("search_03")

def test_found():
    assert mod.jump_search([2, 4, 6, 8, 10], 8) == 3


def test_first():
    assert mod.jump_search([2, 4, 6, 8, 10], 2) == 0


def test_missing():
    assert mod.jump_search([2, 4, 6, 8, 10], 9) == -1


def test_empty():
    assert mod.jump_search([], 5) == -1
