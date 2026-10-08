"""Branch and bound (mock) tests."""

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


mod = _load("search_42")

def test_optimal():
    items = [(60, 10), (100, 20), (120, 30)]
    assert mod.knapsack_branch_bound(items, 50) == 220


def test_tight_capacity():
    items = [(60, 10), (100, 20), (120, 30)]
    assert mod.knapsack_branch_bound(items, 10) == 60


def test_empty():
    assert mod.knapsack_branch_bound([], 50) == 0


def test_negative_capacity():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.knapsack_branch_bound([(1, 1)], -1)
