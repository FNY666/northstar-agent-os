"""Tests for algo_08 (radix sort, base 10)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import algo_08
from algo_08 import radix_sort


def test_01_normal_case():
    assert radix_sort([170, 45, 75, 90, 802, 24, 2, 66]) == [2, 24, 45, 66, 75, 90, 170, 802]
    assert radix_sort([1000, 100, 10, 1]) == [1, 10, 100, 1000]


def test_02_edge_cases():
    assert radix_sort([]) == []
    assert radix_sort([7]) == [7]
    assert radix_sort([0, 0, 5]) == [0, 0, 5]
    assert radix_sort([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]
    assert radix_sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert radix_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]


def test_03_negative_input_raises():
    with pytest.raises(ValueError):
        radix_sort([1, -2, 3])
    with pytest.raises(ValueError):
        radix_sort([-1])


def test_04_does_not_mutate_input():
    src = [4, 2, 3, 1]
    out = radix_sort(src)
    assert src == [4, 2, 3, 1]
    assert out == [1, 2, 3, 4]
    assert out is not src


def test_05_version_and_stdlib_only():
    assert algo_08.ALGO_08_VERSION == "algo-08.v1"
    assert algo_08.stdlib_only() is True
