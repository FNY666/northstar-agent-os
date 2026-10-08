"""Tests for lis-32 (LIS with values restricted to [lo, hi])."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_32
from lis_32 import lis_in_range


def test_01_normal_case():
    assert lis_in_range([5, 1, 4, 2, 3], 2, 4) == 2
    assert lis_in_range([9, 1, 8, 2, 7, 3], 2, 8) == 3
    assert lis_in_range([1, 2, 3], 1, 3) == 3


def test_02_edge_cases():
    assert lis_in_range([], 0, 10) == 0
    assert lis_in_range([1, 2, 3], 5, 9) == 0
    assert lis_in_range([5], 5, 5) == 1


def test_03_validation():
    try:
        lis_in_range([1, 2], 5, 1)
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
    try:
        lis_in_range([1, 2], 'a', 3)
        raise AssertionError('expected ValueError')
    except ValueError:
        pass

def test_04_version_and_stdlib_only():
    assert lis_32.LIS_32_VERSION == "lis-32.v1"
    assert lis_32.stdlib_only() is True
