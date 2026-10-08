"""Tests for algo_11 (linear search)."""

import importlib.util
import sys
from pathlib import Path

MOD = Path(__file__).resolve().parent.parent / "algo_11.py"


def _load():
    spec = importlib.util.spec_from_file_location("algo_11", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algo_11"] = module
    spec.loader.exec_module(module)
    return module


m = _load()


def test_version_and_stdlib_only():
    assert m.ALGO_11_VERSION == "algo-11.v1"
    m.stdlib_only()


def test_found_first_middle_last():
    arr = [10, 20, 30, 40, 50]
    assert m.linear_search(arr, 10) == 0
    assert m.linear_search(arr, 30) == 2
    assert m.linear_search(arr, 50) == 4


def test_target_missing():
    assert m.linear_search([10, 20, 30], 99) == -1
    assert m.linear_search([10, 20, 30], 5) == -1


def test_empty_input():
    assert m.linear_search([], 1) == -1


def test_single_element():
    assert m.linear_search([7], 7) == 0
    assert m.linear_search([7], 8) == -1


def test_returns_first_duplicate():
    assert m.linear_search([1, 2, 2, 3], 2) == 1
