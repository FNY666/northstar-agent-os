"""Tests for algo_04 (merge sort)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import algo_04
from algo_04 import merge_sort


def test_01_normal_case():
    assert merge_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert merge_sort([9, -4, 0, 7, -4, 2]) == [-4, -4, 0, 2, 7, 9]


def test_02_edge_cases():
    assert merge_sort([]) == []
    assert merge_sort([7]) == [7]
    assert merge_sort([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]
    assert merge_sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert merge_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]


def test_03_does_not_mutate_input():
    src = [4, 2, 3, 1]
    out = merge_sort(src)
    assert src == [4, 2, 3, 1]
    assert out == [1, 2, 3, 4]
    assert out is not src


def test_04_version_and_stdlib_only():
    assert algo_04.ALGO_04_VERSION == "algo-04.v1"
    assert algo_04.stdlib_only() is True
