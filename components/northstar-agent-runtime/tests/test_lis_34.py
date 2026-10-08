"""Tests for lis-34 (Minimum increasing-subsequence partition)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_34
from lis_34 import min_increasing_partition


def test_01_normal_case():
    assert min_increasing_partition([3, 1, 2]) == 2
    assert min_increasing_partition([5, 4, 3, 2, 1]) == 5
    assert min_increasing_partition([1, 2, 3, 4]) == 1
    assert min_increasing_partition([2, 1, 4, 3]) == 2


def test_02_edge_cases():
    assert min_increasing_partition([]) == 0
    assert min_increasing_partition([7]) == 1
    assert min_increasing_partition([2, 2, 2]) == 3


def test_03_dilworth_dual():
    from lis_06 import lnis_length
    import random
    random.seed(34)
    for _ in range(10):
        s = [random.randint(0, 8) for _ in range(16)]
        assert min_increasing_partition(s) == lnis_length(s)

def test_04_version_and_stdlib_only():
    assert lis_34.LIS_34_VERSION == "lis-34.v1"
    assert lis_34.stdlib_only() is True
