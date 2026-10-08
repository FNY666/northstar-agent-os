"""Tests for lis-25 (O(n^2) LIS reconstruction)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_25
from lis_25 import lis_reconstruct


def test_01_normal_case():
    r = lis_reconstruct([10, 9, 2, 5, 3, 7, 101, 18])
    assert len(r) == 4
    assert all(r[i] < r[i + 1] for i in range(len(r) - 1))
    r2 = lis_reconstruct([0, 1, 0, 3, 2, 3])
    assert len(r2) == 4


def test_02_edge_cases():
    assert lis_reconstruct([]) == []
    assert lis_reconstruct([5]) == [5]
    assert len(lis_reconstruct([3, 2, 1])) == 1


def test_03_is_subsequence():
    s = [5, 1, 4, 2, 3]
    r = lis_reconstruct(s)
    assert len(r) == 3
    idx = -1
    for v in r:
        idx = s.index(v, idx + 1)
    assert all(r[i] < r[i + 1] for i in range(len(r) - 1))

def test_04_version_and_stdlib_only():
    assert lis_25.LIS_25_VERSION == "lis-25.v1"
    assert lis_25.stdlib_only() is True
