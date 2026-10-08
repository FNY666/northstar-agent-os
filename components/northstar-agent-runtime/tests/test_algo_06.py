"""Tests for algo_06 (heap sort)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import algo_06
from algo_06 import heap_sort


def test_01_normal_case():
    assert heap_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert heap_sort([0, -9, 4, -9, 2]) == [-9, -9, 0, 2, 4]


def test_02_edge_cases():
    assert heap_sort([]) == []
    assert heap_sort([7]) == [7]
    assert heap_sort([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]
    assert heap_sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert heap_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]


def test_03_does_not_mutate_input():
    src = [4, 2, 3, 1]
    out = heap_sort(src)
    assert src == [4, 2, 3, 1]
    assert out == [1, 2, 3, 4]
    assert out is not src


def test_04_version_and_stdlib_only():
    assert algo_06.ALGO_06_VERSION == "algo-06.v1"
    assert algo_06.stdlib_only() is True
