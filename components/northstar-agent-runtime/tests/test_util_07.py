"""util_07 tests."""

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


m = _load("util_07")

def test_chunk():
    assert m.chunk([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]
    assert m.chunk([], 3) == []


def test_dedupe():
    assert m.dedupe([1, 2, 1, 3, 2]) == [1, 2, 3]


def test_partition_window():
    assert m.partition([1, 2, 3, 4], lambda x: x % 2 == 0) == ([2, 4], [1, 3])
    assert m.sliding_window([1, 2, 3], 2) == [[1, 2], [2, 3]]


def test_flatten_one():
    assert m.flatten_one([[1], 2, (3, 4)]) == [1, 2, 3, 4]


def test_stdlib_only():
    assert m.stdlib_only() is True
