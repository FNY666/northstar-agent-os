"""Sentinel linear search tests."""

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


mod = _load("search_08")

def test_found():
    assert mod.sentinel_linear_search([7, 2, 9], 2) == 1


def test_last_is_target():
    assert mod.sentinel_linear_search([7, 2, 9], 9) == 2


def test_not_found():
    assert mod.sentinel_linear_search([7, 2, 9], 5) == -1


def test_empty():
    assert mod.sentinel_linear_search([], 5) == -1
