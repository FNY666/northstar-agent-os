"""Tests for lis-47 (Maximum sum bitonic subsequence)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_47
from lis_47 import max_sum_bitonic


def test_01_normal_case():
    assert max_sum_bitonic([1, 15, 51, 45, 33, 100, 12, 18, 9]) == 194
    assert max_sum_bitonic([1, 2, 3, 2, 1]) == 9
    assert max_sum_bitonic([5, 4, 3, 2, 1]) == 15


def test_02_edge_cases():
    assert max_sum_bitonic([]) == 0
    assert max_sum_bitonic([5]) == 5
    assert max_sum_bitonic([1, 2, 3]) == 6


def test_03_bruteforce():
    import itertools
    s = [4, 1, 5, 2]
    best = max(s) if s else 0
    for r in range(2, len(s) + 1):
        for idx in itertools.combinations(range(len(s)), r):
            v = [s[i] for i in idx]
            for p in range(r):
                up = all(v[k] < v[k + 1] for k in range(p))
                dn = all(v[k] > v[k + 1] for k in range(p, r - 1))
                if up and dn:
                    best = max(best, sum(v))
                    break
    assert max_sum_bitonic(s) == best

def test_04_version_and_stdlib_only():
    assert lis_47.LIS_47_VERSION == "lis-47.v1"
    assert lis_47.stdlib_only() is True
