"""Tests for algo_16 (ternary search)."""

import importlib.util
import sys
from pathlib import Path

MOD = Path(__file__).resolve().parent.parent / "algo_16.py"


def _load():
    spec = importlib.util.spec_from_file_location("algo_16", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algo_16"] = module
    spec.loader.exec_module(module)
    return module


m = _load()


def test_version_and_stdlib_only():
    assert m.ALGO_16_VERSION == "algo-16.v1"
    m.stdlib_only()


def test_found_first_middle_last():
    arr = [1, 2, 4, 8, 16, 32, 64, 128]
    assert m.ternary_search(arr, 1) == 0
    assert m.ternary_search(arr, 16) == 4
    assert m.ternary_search(arr, 128) == 7


def test_target_missing():
    arr = [1, 2, 4, 8, 16, 32, 64, 128]
    assert m.ternary_search(arr, 3) == -1
    assert m.ternary_search(arr, 0) == -1
    assert m.ternary_search(arr, 200) == -1


def test_empty_input():
    assert m.ternary_search([], 1) == -1


def test_single_element():
    assert m.ternary_search([7], 7) == 0
    assert m.ternary_search([7], 2) == -1


def test_two_elements():
    assert m.ternary_search([1, 2], 1) == 0
    assert m.ternary_search([1, 2], 2) == 1
    assert m.ternary_search([1, 2], 3) == -1
