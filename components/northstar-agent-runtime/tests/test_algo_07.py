"""Tests for algo_07 (counting sort)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import algo_07
from algo_07 import counting_sort


def test_01_normal_case():
    assert counting_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert counting_sort([0, 9, 3, 9, 1]) == [0, 1, 3, 9, 9]


def test_02_edge_cases():
    assert counting_sort([]) == []
    assert counting_sort([7]) == [7]
    assert counting_sort([0, 0, 0]) == [0, 0, 0]
    assert counting_sort([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]
    assert counting_sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert counting_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]


def test_03_negative_input_raises():
    with pytest.raises(ValueError):
        counting_sort([1, -2, 3])
    with pytest.raises(ValueError):
        counting_sort([-1])


def test_04_does_not_mutate_input():
    src = [4, 2, 3, 1]
    out = counting_sort(src)
    assert src == [4, 2, 3, 1]
    assert out == [1, 2, 3, 4]
    assert out is not src


def test_05_version_and_stdlib_only():
    assert algo_07.ALGO_07_VERSION == "algo-07.v1"
    assert algo_07.stdlib_only() is True
