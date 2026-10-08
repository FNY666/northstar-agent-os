"""Tests for lis-16 (LIS with minimum consecutive gap)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_16
from lis_16 import lis_min_gap


def test_01_normal_case():
    assert lis_min_gap([1, 2, 3, 4, 5], 2) == 3
    assert lis_min_gap([1, 4, 6, 10], 3) == 3
    assert lis_min_gap([1, 2, 3, 4, 5], 0) == 5


def test_02_edge_cases():
    assert lis_min_gap([], 2) == 0
    assert lis_min_gap([9], 5) == 1
    assert lis_min_gap([1, 2, 3], 10) == 1


def test_03_validation():
    try:
        lis_min_gap([1, 2], -2)
        raise AssertionError('expected ValueError')
    except ValueError:
        pass

def test_04_version_and_stdlib_only():
    assert lis_16.LIS_16_VERSION == "lis-16.v1"
    assert lis_16.stdlib_only() is True
