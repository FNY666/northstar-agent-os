"""Tests for lis-26 (Longest strictly increasing contiguous run)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_26
from lis_26 import longest_increasing_run


def test_01_normal_case():
    assert longest_increasing_run([1, 3, 5, 4, 7]) == 3
    assert longest_increasing_run([1, 3, 5, 7, 2, 4, 6, 8]) == 4
    assert longest_increasing_run([10, 9, 2, 5, 3, 7, 101, 18]) == 2


def test_02_edge_cases():
    assert longest_increasing_run([]) == 0
    assert longest_increasing_run([5]) == 1
    assert longest_increasing_run([5, 4, 3]) == 1
    assert longest_increasing_run([1, 1, 1]) == 1


def test_03_never_exceeds_lis():
    from lis_01 import lis_length
    s = [3, 1, 4, 1, 5, 9, 2, 6]
    assert longest_increasing_run(s) <= lis_length(s)

def test_04_version_and_stdlib_only():
    assert lis_26.LIS_26_VERSION == "lis-26.v1"
    assert lis_26.stdlib_only() is True
