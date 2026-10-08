"""Subset-sum backtracking tests."""

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


mod = _load("search_44")

def test_found():
    r = mod.subset_sum([3, 34, 4, 12, 5, 2], 9)
    assert r is not None and sum(r) == 9


def test_not_found():
    assert mod.subset_sum([1, 2, 3], 100) is None


def test_zero_target():
    assert mod.subset_sum([1, 2], 0) == []


def test_none_nums():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.subset_sum(None, 5)
