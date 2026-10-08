"""Tests for lis-05 (Longest strictly decreasing subsequence)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_05
from lis_05 import lds_length


def test_01_normal_case():
    assert lds_length([10, 9, 2, 5, 3, 7, 101, 18]) == 4
    assert lds_length([5, 4, 3, 2, 1]) == 5
    assert lds_length([1, 3, 2, 4, 0]) == 3


def test_02_edge_cases():
    assert lds_length([]) == 0
    assert lds_length([8]) == 1
    assert lds_length([1, 2, 3, 4]) == 1
    assert lds_length([2, 2, 2]) == 1


def test_03_duality():
    from lis_02 import lis_length_fast
    s = [9, 1, 8, 2, 7, 3]
    assert lds_length(s) == lis_length_fast([-x for x in s])

def test_04_version_and_stdlib_only():
    assert lis_05.LIS_05_VERSION == "lis-05.v1"
    assert lis_05.stdlib_only() is True
