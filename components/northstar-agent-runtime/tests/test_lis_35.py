"""Tests for lis-35 (Minimum decreasing-subsequence partition)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_35
from lis_35 import min_decreasing_partition


def test_01_normal_case():
    assert min_decreasing_partition([1, 2, 3]) == 3
    assert min_decreasing_partition([3, 2, 1]) == 1
    assert min_decreasing_partition([3, 1, 2]) == 2
    assert min_decreasing_partition([2, 3, 1]) == 2


def test_02_edge_cases():
    assert min_decreasing_partition([]) == 0
    assert min_decreasing_partition([7]) == 1
    assert min_decreasing_partition([2, 2, 2]) == 3


def test_03_dilworth_dual():
    from lis_01 import lis_length
    import random
    random.seed(35)
    for _ in range(10):
        s = [random.randint(0, 8) for _ in range(16)]
        assert min_decreasing_partition(s) == lis_length(s)

def test_04_version_and_stdlib_only():
    assert lis_35.LIS_35_VERSION == "lis-35.v1"
    assert lis_35.stdlib_only() is True
