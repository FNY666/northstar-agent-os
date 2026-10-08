"""Tests for lis-01 (Classic O(n^2) LIS length)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_01
from lis_01 import lis_length


def test_01_normal_case():
    assert lis_length([10, 9, 2, 5, 3, 7, 101, 18]) == 4
    assert lis_length([0, 1, 0, 3, 2, 3]) == 4
    assert lis_length([7, 7, 7, 7, 7, 7, 7]) == 1


def test_02_edge_cases():
    assert lis_length([]) == 0
    assert lis_length([42]) == 1
    assert lis_length([5, 4, 3, 2, 1]) == 1
    assert lis_length([-3, -2, -1, 0]) == 4


def test_03_validation():
    try:
        lis_length('nope')
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
    try:
        lis_length([1, 'x'])
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
    assert lis_length((3, 1, 2)) == 2

def test_04_version_and_stdlib_only():
    assert lis_01.LIS_01_VERSION == "lis-01.v1"
    assert lis_01.stdlib_only() is True
