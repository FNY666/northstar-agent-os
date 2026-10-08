"""Tests for lis-49 (LIS of length exactly K)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_49
from lis_49 import lis_exact_k


def test_01_normal_case():
    r = lis_exact_k([10, 9, 2, 5, 3, 7, 101, 18], 4)
    assert r is not None and len(r) == 4
    assert all(r[i] < r[i + 1] for i in range(3))
    r2 = lis_exact_k([1, 2, 3, 4], 2)
    assert r2 is not None and len(r2) == 2


def test_02_edge_cases():
    assert lis_exact_k([1, 2, 3], 0) == []
    assert lis_exact_k([], 0) == []
    assert lis_exact_k([], 1) is None
    assert lis_exact_k([1, 2, 3], 5) is None
    assert lis_exact_k([5], 1) == [5]


def test_03_is_subsequence():
    s = [3, 1, 4, 1, 5, 9, 2, 6]
    r = lis_exact_k(s, 3)
    assert r is not None and len(r) == 3
    idx = -1
    for v in r:
        idx = s.index(v, idx + 1)
    try:
        lis_exact_k([1], -1)
        raise AssertionError('expected ValueError')
    except ValueError:
        pass

def test_04_version_and_stdlib_only():
    assert lis_49.LIS_49_VERSION == "lis-49.v1"
    assert lis_49.stdlib_only() is True
