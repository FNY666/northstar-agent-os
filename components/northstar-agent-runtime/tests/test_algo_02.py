"""Tests for algo_02 (insertion sort)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import algo_02
from algo_02 import insertion_sort


def test_01_normal_case():
    assert insertion_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert insertion_sort([0, -1, -1, 5]) == [-1, -1, 0, 5]


def test_02_edge_cases():
    assert insertion_sort([]) == []
    assert insertion_sort([7]) == [7]
    assert insertion_sort([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]
    assert insertion_sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert insertion_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]


def test_03_does_not_mutate_input():
    src = [4, 2, 3, 1]
    out = insertion_sort(src)
    assert src == [4, 2, 3, 1]
    assert out == [1, 2, 3, 4]
    assert out is not src


def test_04_version_and_stdlib_only():
    assert algo_02.ALGO_02_VERSION == "algo-02.v1"
    assert algo_02.stdlib_only() is True
