"""util_25 tests."""

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


m = _load("util_25")

def test_jaccard():
    assert m.jaccard({1, 2}, {2, 3}) == 1 / 3
    assert m.jaccard(set(), set()) == 1.0
    assert m.jaccard({1}, {1}) == 1.0


def test_overlap():
    assert m.overlap([1, 2, 3], [2, 4]) == {2}


def test_difference_all():
    assert m.difference_all({1, 2, 3}, {2}, {3}) == {1}


def test_subset_of_any():
    assert m.is_subset_of_any({1}, [{1, 2}, {3}]) is True
    assert m.is_subset_of_any({9}, [{1, 2}]) is False


def test_stdlib_only():
    assert m.stdlib_only() is True
