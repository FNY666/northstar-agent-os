"""Tests for lis-18 (Decision: LIS of length at least K exists)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_18
from lis_18 import has_lis_of_length


def test_01_normal_case():
    assert has_lis_of_length([10, 9, 2, 5, 3, 7, 101, 18], 4) is True
    assert has_lis_of_length([10, 9, 2, 5, 3, 7, 101, 18], 5) is False
    assert has_lis_of_length([1, 2, 3], 3) is True


def test_02_edge_cases():
    assert has_lis_of_length([], 0) is True
    assert has_lis_of_length([], 1) is False
    assert has_lis_of_length([5], 1) is True
    assert has_lis_of_length([5], 2) is False


def test_03_validation():
    try:
        has_lis_of_length([1, 2], -1)
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
    try:
        has_lis_of_length([1, 2], 1.5)
        raise AssertionError('expected ValueError')
    except ValueError:
        pass

def test_04_version_and_stdlib_only():
    assert lis_18.LIS_18_VERSION == "lis-18.v1"
    assert lis_18.stdlib_only() is True
