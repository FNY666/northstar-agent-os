"""Tests for lis-12 (Longest alternating (wiggle) subsequence)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_12
from lis_12 import longest_wiggle


def test_01_normal_case():
    assert longest_wiggle([1, 7, 4, 9, 2, 5]) == 6
    assert longest_wiggle([1, 17, 5, 10, 13, 15, 10, 5, 16, 8]) == 7
    assert longest_wiggle([1, 2, 3, 4, 5, 6, 7, 8, 9]) == 2


def test_02_edge_cases():
    assert longest_wiggle([]) == 0
    assert longest_wiggle([4]) == 1
    assert longest_wiggle([3, 3, 3, 3]) == 1
    assert longest_wiggle([1, 2]) == 2
    assert longest_wiggle([2, 1]) == 2


def test_03_bruteforce():
    import itertools
    s = [3, 1, 4, 2]
    best = 1 if s else 0
    for r in range(2, len(s) + 1):
        for idx in itertools.combinations(range(len(s)), r):
            v = [s[i] for i in idx]
            ok = all(v[k] != v[k + 1] for k in range(r - 1))
            ok = ok and all((v[k] - v[k - 1]) * (v[k + 1] - v[k]) < 0 for k in range(1, r - 1))
            if ok:
                best = r
    assert longest_wiggle(s) == best

def test_04_version_and_stdlib_only():
    assert lis_12.LIS_12_VERSION == "lis-12.v1"
    assert lis_12.stdlib_only() is True
