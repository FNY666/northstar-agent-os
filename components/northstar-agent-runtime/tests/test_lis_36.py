"""Tests for lis-36 (LIS length of each prefix)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_36
from lis_36 import lis_prefix_lengths


def test_01_normal_case():
    assert lis_prefix_lengths([3, 1, 2]) == [1, 1, 2]
    assert lis_prefix_lengths([10, 9, 2, 5, 3, 7, 101, 18]) == [1, 1, 1, 2, 2, 3, 4, 4]
    assert lis_prefix_lengths([5, 4, 3]) == [1, 1, 1]


def test_02_edge_cases():
    assert lis_prefix_lengths([]) == []
    assert lis_prefix_lengths([9]) == [1]
    assert lis_prefix_lengths([2, 2, 2]) == [1, 1, 1]


def test_03_monotone_and_final():
    from lis_01 import lis_length
    s = [4, 1, 5, 2, 6, 3]
    r = lis_prefix_lengths(s)
    assert all(r[i] <= r[i + 1] for i in range(len(r) - 1))
    assert r[-1] == lis_length(s)

def test_04_version_and_stdlib_only():
    assert lis_36.LIS_36_VERSION == "lis-36.v1"
    assert lis_36.stdlib_only() is True
