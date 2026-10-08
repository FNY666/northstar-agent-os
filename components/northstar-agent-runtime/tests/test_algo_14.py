"""Tests for algo_14 (interpolation search)."""

import importlib.util
import sys
from pathlib import Path

MOD = Path(__file__).resolve().parent.parent / "algo_14.py"


def _load():
    spec = importlib.util.spec_from_file_location("algo_14", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algo_14"] = module
    spec.loader.exec_module(module)
    return module


m = _load()


def test_version_and_stdlib_only():
    assert m.ALGO_14_VERSION == "algo-14.v1"
    m.stdlib_only()


def test_found_first_middle_last():
    arr = list(range(0, 100, 2))
    assert m.interpolation_search(arr, 0) == 0
    assert m.interpolation_search(arr, 50) == 25
    assert m.interpolation_search(arr, 98) == 49


def test_target_missing():
    arr = list(range(0, 100, 2))
    assert m.interpolation_search(arr, 51) == -1
    assert m.interpolation_search(arr, -2) == -1
    assert m.interpolation_search(arr, 200) == -1


def test_empty_input():
    assert m.interpolation_search([], 1) == -1


def test_single_element():
    assert m.interpolation_search([9], 9) == 0
    assert m.interpolation_search([9], 3) == -1


def test_constant_run():
    assert m.interpolation_search([5, 5, 5, 5], 5) == 0
    assert m.interpolation_search([5, 5, 5, 5], 6) == -1
