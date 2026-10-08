"""Tests for lis-31 (Longest doubling chain)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_31
from lis_31 import longest_doubling_chain


def test_01_normal_case():
    assert longest_doubling_chain([2, 4, 8, 16]) == 4
    assert longest_doubling_chain([1, 3, 6, 12, 25]) == 4
    assert longest_doubling_chain([1, 2, 3, 4, 8]) == 4


def test_02_edge_cases():
    assert longest_doubling_chain([]) == 0
    assert longest_doubling_chain([5]) == 1
    assert longest_doubling_chain([3, 5, 7]) == 2
    assert longest_doubling_chain([-4, 1, 2, 4]) == 3


def test_03_never_exceeds_lis():
    from lis_01 import lis_length
    s = [1, 2, 4, 3, 8, 6]
    assert longest_doubling_chain(s) <= lis_length(s)

def test_04_version_and_stdlib_only():
    assert lis_31.LIS_31_VERSION == "lis-31.v1"
    assert lis_31.stdlib_only() is True
