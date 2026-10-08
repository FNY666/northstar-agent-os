"""Tests for algo_03 (selection sort)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import algo_03
from algo_03 import selection_sort


def test_01_normal_case():
    assert selection_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert selection_sort([-3, -1, -2]) == [-3, -2, -1]


def test_02_edge_cases():
    assert selection_sort([]) == []
    assert selection_sort([7]) == [7]
    assert selection_sort([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]
    assert selection_sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert selection_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]


def test_03_does_not_mutate_input():
    src = [4, 2, 3, 1]
    out = selection_sort(src)
    assert src == [4, 2, 3, 1]
    assert out == [1, 2, 3, 4]
    assert out is not src


def test_04_version_and_stdlib_only():
    assert algo_03.ALGO_03_VERSION == "algo-03.v1"
    assert algo_03.stdlib_only() is True
