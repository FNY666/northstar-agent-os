"""Tests for algo_13 (jump search)."""

import importlib.util
import sys
from pathlib import Path

MOD = Path(__file__).resolve().parent.parent / "algo_13.py"


def _load():
    spec = importlib.util.spec_from_file_location("algo_13", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algo_13"] = module
    spec.loader.exec_module(module)
    return module


m = _load()


def test_version_and_stdlib_only():
    assert m.ALGO_13_VERSION == "algo-13.v1"
    m.stdlib_only()


def test_found_first_middle_last():
    arr = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
    assert m.jump_search(arr, 2) == 0
    assert m.jump_search(arr, 10) == 4
    assert m.jump_search(arr, 20) == 9


def test_target_missing():
    arr = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
    assert m.jump_search(arr, 7) == -1
    assert m.jump_search(arr, 1) == -1
    assert m.jump_search(arr, 21) == -1


def test_empty_input():
    assert m.jump_search([], 3) == -1


def test_single_element():
    assert m.jump_search([5], 5) == 0
    assert m.jump_search([5], 6) == -1


def test_non_square_length():
    arr = [1, 2, 3, 4, 5, 6, 7]
    assert m.jump_search(arr, 1) == 0
    assert m.jump_search(arr, 4) == 3
    assert m.jump_search(arr, 7) == 6
    assert m.jump_search(arr, 8) == -1
