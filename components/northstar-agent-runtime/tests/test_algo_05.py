"""Tests for algo_05 (quick sort)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import algo_05
from algo_05 import quick_sort


def test_01_normal_case():
    assert quick_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert quick_sort([-5, 3, -5, 0, 2]) == [-5, -5, 0, 2, 3]


def test_02_edge_cases():
    assert quick_sort([]) == []
    assert quick_sort([7]) == [7]
    assert quick_sort([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]
    assert quick_sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert quick_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]


def test_03_pathological_inputs_no_recursion_blowup():
    assert quick_sort(list(range(3000))) == list(range(3000))
    assert quick_sort(list(range(3000, 0, -1))) == list(range(1, 3001))
    assert quick_sort([9] * 3000) == [9] * 3000


def test_04_does_not_mutate_input():
    src = [4, 2, 3, 1]
    out = quick_sort(src)
    assert src == [4, 2, 3, 1]
    assert out == [1, 2, 3, 4]
    assert out is not src


def test_05_version_and_stdlib_only():
    assert algo_05.ALGO_05_VERSION == "algo-05.v1"
    assert algo_05.stdlib_only() is True
