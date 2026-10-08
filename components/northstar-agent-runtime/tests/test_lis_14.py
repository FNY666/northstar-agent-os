"""Tests for lis-14 (LIS length starting at each position)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_14
from lis_14 import lis_starting_at


def test_01_normal_case():
    assert lis_starting_at([10, 9, 2, 5, 3, 7, 101, 18]) == [2, 2, 4, 3, 3, 2, 1, 1]
    assert lis_starting_at([1, 2, 3]) == [3, 2, 1]
    assert lis_starting_at([3, 2, 1]) == [1, 1, 1]


def test_02_edge_cases():
    assert lis_starting_at([]) == []
    assert lis_starting_at([5]) == [1]
    assert lis_starting_at([2, 1, 3]) == [2, 1, 1]


def test_03_max_is_lis():
    from lis_01 import lis_length
    s = [6, 2, 5, 1, 7, 4]
    assert max(lis_starting_at(s)) == lis_length(s)

def test_04_version_and_stdlib_only():
    assert lis_14.LIS_14_VERSION == "lis-14.v1"
    assert lis_14.stdlib_only() is True
