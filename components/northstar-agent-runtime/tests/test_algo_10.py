"""Tests for algo_10 (shell sort)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import algo_10
from algo_10 import shell_sort


def test_01_normal_case():
    assert shell_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert shell_sort([12, -3, 0, 7, -3, 9]) == [-3, -3, 0, 7, 9, 12]


def test_02_edge_cases():
    assert shell_sort([]) == []
    assert shell_sort([7]) == [7]
    assert shell_sort([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]
    assert shell_sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert shell_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]


def test_03_does_not_mutate_input():
    src = [4, 2, 3, 1]
    out = shell_sort(src)
    assert src == [4, 2, 3, 1]
    assert out == [1, 2, 3, 4]
    assert out is not src


def test_04_version_and_stdlib_only():
    assert algo_10.ALGO_10_VERSION == "algo-10.v1"
    assert algo_10.stdlib_only() is True
