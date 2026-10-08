"""Peak element search tests."""

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


mod = _load("search_10")

def _is_peak(items, i):
    left = i == 0 or items[i - 1] <= items[i]
    right = i == len(items) - 1 or items[i + 1] <= items[i]
    return left and right


def test_peak():
    items = [1, 2, 1, 3, 5, 6, 4]
    assert _is_peak(items, mod.peak_element(items))


def test_single():
    assert mod.peak_element([9]) == 0


def test_two():
    assert mod.peak_element([1, 2]) == 1


def test_empty_raises():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.peak_element([])
