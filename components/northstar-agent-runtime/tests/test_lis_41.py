"""Tests for lis-41 (Longest increasing path in a matrix)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_41
from lis_41 import longest_increasing_path


def test_01_normal_case():
    assert longest_increasing_path([[9, 9, 4], [6, 6, 8], [2, 1, 1]]) == 4
    assert longest_increasing_path([[3, 4, 5], [3, 2, 6], [2, 2, 1]]) == 4
    assert longest_increasing_path([[1]]) == 1


def test_02_edge_cases():
    assert longest_increasing_path([]) == 0
    assert longest_increasing_path([[]]) == 0
    assert longest_increasing_path([[7, 7], [7, 7]]) == 1
    assert longest_increasing_path([[1, 2], [3, 4]]) == 3


def test_03_validation():
    try:
        longest_increasing_path([[1, 2], [3]])
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
    try:
        longest_increasing_path([['a']])
        raise AssertionError('expected ValueError')
    except ValueError:
        pass

def test_04_version_and_stdlib_only():
    assert lis_41.LIS_41_VERSION == "lis-41.v1"
    assert lis_41.stdlib_only() is True
