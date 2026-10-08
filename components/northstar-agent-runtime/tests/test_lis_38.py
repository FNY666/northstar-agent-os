"""Tests for lis-38 (Count of longest non-decreasing subsequences)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_38
from lis_38 import count_lnds


def test_01_normal_case():
    assert count_lnds([1, 2, 2]) == 1
    assert count_lnds([1, 3, 2, 3]) == 2
    assert count_lnds([1, 2, 3]) == 1


def test_02_edge_cases():
    assert count_lnds([]) == 0
    assert count_lnds([9]) == 1
    assert count_lnds([2, 2, 2]) == 1
    assert count_lnds([3, 2, 1]) == 3


def test_03_bruteforce():
    import itertools
    s = [2, 1, 2, 1]
    best, ways = 0, 0
    for r in range(1, len(s) + 1):
        for idx in itertools.combinations(range(len(s)), r):
            v = [s[i] for i in idx]
            if all(v[k] <= v[k + 1] for k in range(r - 1)):
                if r > best:
                    best, ways = r, 1
                elif r == best:
                    ways += 1
    assert count_lnds(s) == ways

def test_04_version_and_stdlib_only():
    assert lis_38.LIS_38_VERSION == "lis-38.v1"
    assert lis_38.stdlib_only() is True
