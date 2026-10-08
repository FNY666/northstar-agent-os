"""Tests for lis-33 (Longest valley subsequence)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_33
from lis_33 import longest_valley


def test_01_normal_case():
    assert longest_valley([5, 3, 1, 2, 4]) == 5
    assert longest_valley([9, 5, 1, 4, 8]) == 5
    assert longest_valley([3, 1, 2]) == 3


def test_02_edge_cases():
    assert longest_valley([]) == 0
    assert longest_valley([7]) == 1
    assert longest_valley([1, 2, 3]) == 3
    assert longest_valley([3, 2, 1]) == 3


def test_03_bruteforce():
    import itertools
    s = [4, 1, 3, 2]
    best = 1 if s else 0
    for r in range(1, len(s) + 1):
        for idx in itertools.combinations(range(len(s)), r):
            v = [s[i] for i in idx]
            for p in range(r):
                dn = all(v[k] > v[k + 1] for k in range(p))
                up = all(v[k] < v[k + 1] for k in range(p, r - 1))
                if dn and up:
                    best = max(best, r)
                    break
    assert longest_valley(s) == best

def test_04_version_and_stdlib_only():
    assert lis_33.LIS_33_VERSION == "lis-33.v1"
    assert lis_33.stdlib_only() is True
