"""Tests for algo_15 (exponential search)."""

import importlib.util
import sys
from pathlib import Path

MOD = Path(__file__).resolve().parent.parent / "algo_15.py"


def _load():
    spec = importlib.util.spec_from_file_location("algo_15", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algo_15"] = module
    spec.loader.exec_module(module)
    return module


m = _load()


def test_version_and_stdlib_only():
    assert m.ALGO_15_VERSION == "algo-15.v1"
    m.stdlib_only()


def test_found_first_middle_last():
    arr = [3, 6, 9, 12, 15, 18, 21, 24, 27, 30]
    assert m.exponential_search(arr, 3) == 0
    assert m.exponential_search(arr, 15) == 4
    assert m.exponential_search(arr, 30) == 9


def test_target_missing():
    arr = [3, 6, 9, 12, 15, 18, 21, 24, 27, 30]
    assert m.exponential_search(arr, 16) == -1
    assert m.exponential_search(arr, 1) == -1
    assert m.exponential_search(arr, 31) == -1


def test_empty_input():
    assert m.exponential_search([], 3) == -1


def test_single_element():
    assert m.exponential_search([11], 11) == 0
    assert m.exponential_search([11], 5) == -1


def test_target_near_front_long_list():
    arr = list(range(1000))
    assert m.exponential_search(arr, 1) == 1
    assert m.exponential_search(arr, 999) == 999
    assert m.exponential_search(arr, 1001) == -1
