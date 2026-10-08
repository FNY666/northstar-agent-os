"""Tests for algo_12 (iterative binary search)."""

import importlib.util
import sys
from pathlib import Path

MOD = Path(__file__).resolve().parent.parent / "algo_12.py"


def _load():
    spec = importlib.util.spec_from_file_location("algo_12", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algo_12"] = module
    spec.loader.exec_module(module)
    return module


m = _load()


def test_version_and_stdlib_only():
    assert m.ALGO_12_VERSION == "algo-12.v1"
    m.stdlib_only()


def test_found_first_middle_last():
    arr = [1, 3, 5, 7, 9, 11, 13]
    assert m.binary_search(arr, 1) == 0
    assert m.binary_search(arr, 7) == 3
    assert m.binary_search(arr, 13) == 6


def test_target_missing():
    arr = [1, 3, 5, 7, 9, 11, 13]
    assert m.binary_search(arr, 8) == -1
    assert m.binary_search(arr, 0) == -1
    assert m.binary_search(arr, 100) == -1


def test_empty_input():
    assert m.binary_search([], 5) == -1


def test_single_element():
    assert m.binary_search([42], 42) == 0
    assert m.binary_search([42], 7) == -1


def test_even_length_list():
    arr = [2, 4, 6, 8]
    assert m.binary_search(arr, 2) == 0
    assert m.binary_search(arr, 8) == 3
    assert m.binary_search(arr, 5) == -1
