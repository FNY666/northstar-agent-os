"""Block sort (simplified) tests."""

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


m = _load("sort_44")


def test_empty():
    assert m.sort([]) == []


def test_single():
    assert m.sort([7]) == [7]


def test_sorted_input():
    assert m.sort([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]


def test_reverse():
    assert m.sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]


def test_duplicates_negatives():
    assert m.sort([3, -1, 2, -1, 0, 3]) == [-1, -1, 0, 2, 3, 3]


def test_does_not_mutate_input():
    data = [3, 1, 2]
    m.sort(data)
    assert data == [3, 1, 2]


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.SORT_44_VERSION == "sort-44.v1"

