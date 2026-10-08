"""Tests for lis-30 (LIS over odd values only)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_30
from lis_30 import lis_odd_only


def test_01_normal_case():
    assert lis_odd_only([1, 2, 3, 4, 5]) == 3
    assert lis_odd_only([5, 2, 3, 4, 1]) == 2
    assert lis_odd_only([1, 3, 5, 7]) == 4


def test_02_edge_cases():
    assert lis_odd_only([]) == 0
    assert lis_odd_only([2, 4, 6]) == 0
    assert lis_odd_only([7]) == 1
    assert lis_odd_only([-3, -1, 1]) == 3


def test_03_never_exceeds_full():
    from lis_01 import lis_length
    s = [5, 2, 8, 1, 4]
    assert lis_odd_only(s) <= lis_length(s)

def test_04_version_and_stdlib_only():
    assert lis_30.LIS_30_VERSION == "lis-30.v1"
    assert lis_30.stdlib_only() is True
