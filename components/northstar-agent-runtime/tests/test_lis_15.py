"""Tests for lis-15 (LIS with bounded consecutive gap)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_15
from lis_15 import lis_bounded_gap


def test_01_normal_case():
    assert lis_bounded_gap([1, 2, 3, 4, 5], 1) == 5
    assert lis_bounded_gap([1, 3, 6, 7, 9], 3) == 5
    assert lis_bounded_gap([1, 10, 11, 20], 2) == 2


def test_02_edge_cases():
    assert lis_bounded_gap([], 3) == 0
    assert lis_bounded_gap([5], 0) == 1
    assert lis_bounded_gap([1, 1, 1], 0) == 1
    assert lis_bounded_gap([1, 2, 3], 100) == 3


def test_03_validation():
    try:
        lis_bounded_gap([1, 2], -1)
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
    try:
        lis_bounded_gap([1, 2], 'x')
        raise AssertionError('expected ValueError')
    except ValueError:
        pass

def test_04_version_and_stdlib_only():
    assert lis_15.LIS_15_VERSION == "lis-15.v1"
    assert lis_15.stdlib_only() is True
