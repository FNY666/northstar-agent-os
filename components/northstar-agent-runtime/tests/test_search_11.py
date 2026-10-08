"""Lower/upper bound tests."""

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


mod = _load("search_11")

def test_lower():
    assert mod.lower_bound([1, 2, 2, 4], 2) == 1


def test_upper():
    assert mod.upper_bound([1, 2, 2, 4], 2) == 3


def test_missing_target():
    assert mod.lower_bound([1, 3, 5], 4) == 2
    assert mod.upper_bound([1, 3, 5], 4) == 2


def test_empty():
    assert mod.lower_bound([], 1) == 0
    assert mod.upper_bound([], 1) == 0
