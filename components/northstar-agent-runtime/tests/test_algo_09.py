"""Tests for algo_09 (bucket sort)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import algo_09
from algo_09 import bucket_sort


def test_01_floats_in_unit_interval():
    assert bucket_sort([0.42, 0.13, 0.87, 0.02, 0.55]) == [0.02, 0.13, 0.42, 0.55, 0.87]
    assert bucket_sort([0.9, 0.1, 0.5, 0.3]) == [0.1, 0.3, 0.5, 0.9]


def test_02_ints_any_range():
    assert bucket_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert bucket_sort([-10, 7, 0, -3]) == [-10, -3, 0, 7]
    assert bucket_sort([4, 4, 4, 4]) == [4, 4, 4, 4]


def test_03_edge_cases():
    assert bucket_sort([]) == []
    assert bucket_sort([0.5]) == [0.5]
    assert bucket_sort([7]) == [7]
    assert bucket_sort([0.1, 0.2, 0.3, 0.4]) == [0.1, 0.2, 0.3, 0.4]
    assert bucket_sort([0.4, 0.3, 0.2, 0.1]) == [0.1, 0.2, 0.3, 0.4]
    assert bucket_sort([0.3, 0.1, 0.3, 0.2]) == [0.1, 0.2, 0.3, 0.3]


def test_04_does_not_mutate_input():
    src = [0.3, 0.1, 0.2]
    out = bucket_sort(src)
    assert src == [0.3, 0.1, 0.2]
    assert out == [0.1, 0.2, 0.3]
    assert out is not src


def test_05_version_and_stdlib_only():
    assert algo_09.ALGO_09_VERSION == "algo-09.v1"
    assert algo_09.stdlib_only() is True
