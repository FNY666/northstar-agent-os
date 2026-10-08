"""Tests for lis-19 (Longest divisible subset length)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_19
from lis_19 import longest_divisible_subset_len


def test_01_normal_case():
    assert longest_divisible_subset_len([1, 2, 3]) == 2
    assert longest_divisible_subset_len([1, 2, 4, 8]) == 4
    assert longest_divisible_subset_len([4, 8, 10, 240]) == 3


def test_02_edge_cases():
    assert longest_divisible_subset_len([]) == 0
    assert longest_divisible_subset_len([7]) == 1
    assert longest_divisible_subset_len([2, 3, 5, 7]) == 1


def test_03_validation():
    try:
        longest_divisible_subset_len([1, -2])
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
    try:
        longest_divisible_subset_len([0, 2])
        raise AssertionError('expected ValueError')
    except ValueError:
        pass

def test_04_version_and_stdlib_only():
    assert lis_19.LIS_19_VERSION == "lis-19.v1"
    assert lis_19.stdlib_only() is True
