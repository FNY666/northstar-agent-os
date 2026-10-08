"""Tests for lis-45 (Longest fixed-difference chain)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_45
from lis_45 import longest_diff_d_chain


def test_01_normal_case():
    assert longest_diff_d_chain([1, 3, 5, 7], 2) == 4
    assert longest_diff_d_chain([1, 2, 3, 4, 5], 2) == 3
    assert longest_diff_d_chain([5, 3, 1], -2) == 3


def test_02_edge_cases():
    assert longest_diff_d_chain([], 2) == 0
    assert longest_diff_d_chain([7], 3) == 1
    assert longest_diff_d_chain([1, 1, 1], 0) == 3
    assert longest_diff_d_chain([1, 2, 4], 5) == 1


def test_03_validation():
    try:
        longest_diff_d_chain([1, 2], 'x')
        raise AssertionError('expected ValueError')
    except ValueError:
        pass

def test_04_version_and_stdlib_only():
    assert lis_45.LIS_45_VERSION == "lis-45.v1"
    assert lis_45.stdlib_only() is True
