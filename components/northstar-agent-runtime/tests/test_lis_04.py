"""Tests for lis-04 (Longest non-decreasing subsequence)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_04
from lis_04 import lnds_length


def test_01_normal_case():
    assert lnds_length([1, 2, 2, 3]) == 4
    assert lnds_length([1, 3, 2, 2, 2, 4]) == 5
    assert lnds_length([5, 5, 5]) == 3


def test_02_edge_cases():
    assert lnds_length([]) == 0
    assert lnds_length([7]) == 1
    assert lnds_length([3, 2, 1]) == 1
    assert lnds_length([-1, -1, 0, 0, 1]) == 5


def test_03_strict_vs_nonstrict():
    assert lnds_length([1, 1, 1, 2]) == 4
    from lis_02 import lis_length_fast
    assert lis_length_fast([1, 1, 1, 2]) == 2

def test_04_version_and_stdlib_only():
    assert lis_04.LIS_04_VERSION == "lis-04.v1"
    assert lis_04.stdlib_only() is True
