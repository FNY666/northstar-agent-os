"""Tests for lis-08 (Longest bitonic subsequence)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_08
from lis_08 import longest_bitonic


def test_01_normal_case():
    assert longest_bitonic([1, 11, 2, 10, 4, 5, 2, 1]) == 6
    assert longest_bitonic([12, 11, 40, 5, 3, 1]) == 5
    assert longest_bitonic([80, 60, 30, 40, 20, 10]) == 5


def test_02_edge_cases():
    assert longest_bitonic([]) == 0
    assert longest_bitonic([7]) == 1
    assert longest_bitonic([1, 2, 3, 4]) == 4
    assert longest_bitonic([4, 3, 2, 1]) == 4


def test_03_mountain():
    assert longest_bitonic([1, 3, 5, 4, 2]) == 5
    assert longest_bitonic([2, 2, 2]) == 1

def test_04_version_and_stdlib_only():
    assert lis_08.LIS_08_VERSION == "lis-08.v1"
    assert lis_08.stdlib_only() is True
