"""Tests for lis-03 (O(n log n) LIS reconstruction)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_03
from lis_03 import lis_subsequence


def test_01_normal_case():
    r = lis_subsequence([10, 9, 2, 5, 3, 7, 101, 18])
    assert len(r) == 4
    assert all(r[i] < r[i + 1] for i in range(len(r) - 1))
    it = iter([10, 9, 2, 5, 3, 7, 101, 18])
    assert all(any(v == x for v in it) for x in r)


def test_02_edge_cases():
    assert lis_subsequence([]) == []
    assert lis_subsequence([5]) == [5]
    assert lis_subsequence([3, 2, 1]) == [1]
    r = lis_subsequence([1, 2, 3])
    assert r == [1, 2, 3]


def test_03_is_subsequence():
    s = [3, 1, 4, 1, 5, 9, 2, 6]
    r = lis_subsequence(s)
    assert len(r) == 4
    idx = -1
    sa = list(s)
    for v in r:
        idx = sa.index(v, idx + 1)
    assert all(r[i] < r[i + 1] for i in range(len(r) - 1))

def test_04_version_and_stdlib_only():
    assert lis_03.LIS_03_VERSION == "lis-03.v1"
    assert lis_03.stdlib_only() is True
