"""Tests for lis-37 (Longest strictly decreasing contiguous run)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_37
from lis_37 import longest_decreasing_run


def test_01_normal_case():
    assert longest_decreasing_run([5, 4, 3, 1, 2]) == 4
    assert longest_decreasing_run([9, 8, 7, 8, 7, 6, 5]) == 4
    assert longest_decreasing_run([1, 3, 2, 4]) == 2


def test_02_edge_cases():
    assert longest_decreasing_run([]) == 0
    assert longest_decreasing_run([5]) == 1
    assert longest_decreasing_run([1, 2, 3]) == 1
    assert longest_decreasing_run([2, 2, 2]) == 1


def test_03_never_exceeds_lds():
    from lis_05 import lds_length
    s = [5, 3, 4, 2, 1]
    assert longest_decreasing_run(s) <= lds_length(s)

def test_04_version_and_stdlib_only():
    assert lis_37.LIS_37_VERSION == "lis-37.v1"
    assert lis_37.stdlib_only() is True
