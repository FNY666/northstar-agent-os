"""Tests for lis-11 (Minimum deletions for strictly increasing)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_11
from lis_11 import min_deletions_increasing


def test_01_normal_case():
    assert min_deletions_increasing([10, 9, 2, 5, 3, 7, 101, 18]) == 4
    assert min_deletions_increasing([5, 4, 3, 2, 1]) == 4
    assert min_deletions_increasing([1, 3, 2, 4]) == 1


def test_02_edge_cases():
    assert min_deletions_increasing([]) == 0
    assert min_deletions_increasing([1]) == 0
    assert min_deletions_increasing([1, 2, 3, 4, 5]) == 0


def test_03_consistency():
    from lis_01 import lis_length
    s = [4, 2, 5, 1, 3]
    assert min_deletions_increasing(s) == len(s) - lis_length(s)

def test_04_version_and_stdlib_only():
    assert lis_11.LIS_11_VERSION == "lis-11.v1"
    assert lis_11.stdlib_only() is True
