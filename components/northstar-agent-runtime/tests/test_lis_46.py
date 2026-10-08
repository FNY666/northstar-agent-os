"""Tests for lis-46 (Longest non-strict bitonic subsequence)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_46
from lis_46 import longest_bitonic_nonstrict


def test_01_normal_case():
    assert longest_bitonic_nonstrict([1, 2, 2, 1]) == 4
    assert longest_bitonic_nonstrict([1, 11, 2, 10, 4, 5, 2, 1]) == 6
    assert longest_bitonic_nonstrict([3, 3, 2, 2, 1]) == 5


def test_02_edge_cases():
    assert longest_bitonic_nonstrict([]) == 0
    assert longest_bitonic_nonstrict([5]) == 1
    assert longest_bitonic_nonstrict([1, 1, 1]) == 3


def test_03_dominates_strict():
    from lis_08 import longest_bitonic
    s = [1, 2, 2, 3, 2, 1]
    assert longest_bitonic_nonstrict(s) >= longest_bitonic(s)

def test_04_version_and_stdlib_only():
    assert lis_46.LIS_46_VERSION == "lis-46.v1"
    assert lis_46.stdlib_only() is True
