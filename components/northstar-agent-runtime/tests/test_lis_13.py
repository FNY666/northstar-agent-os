"""Tests for lis-13 (LIS length ending at each position)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_13
from lis_13 import lis_ending_at


def test_01_normal_case():
    assert lis_ending_at([10, 9, 2, 5, 3, 7, 101, 18]) == [1, 1, 1, 2, 2, 3, 4, 4]
    assert lis_ending_at([1, 2, 3]) == [1, 2, 3]
    assert lis_ending_at([2, 2, 2]) == [1, 1, 1]


def test_02_edge_cases():
    assert lis_ending_at([]) == []
    assert lis_ending_at([5]) == [1]
    r = lis_ending_at([4, 1, 3, 2])
    assert r == [1, 1, 2, 2]


def test_03_max_is_lis():
    from lis_01 import lis_length
    s = [6, 2, 5, 1, 7, 4]
    assert max(lis_ending_at(s)) == lis_length(s)

def test_04_version_and_stdlib_only():
    assert lis_13.LIS_13_VERSION == "lis-13.v1"
    assert lis_13.stdlib_only() is True
