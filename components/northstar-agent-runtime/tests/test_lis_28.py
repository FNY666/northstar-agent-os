"""Tests for lis-28 (Longest mountain subsequence (proper))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_28
from lis_28 import longest_mountain_subseq


def test_01_normal_case():
    assert longest_mountain_subseq([2, 1, 4, 7, 3, 2, 5]) == 5
    assert longest_mountain_subseq([1, 3, 2]) == 3
    assert longest_mountain_subseq([1, 2, 3, 2, 1]) == 5


def test_02_edge_cases():
    assert longest_mountain_subseq([]) == 0
    assert longest_mountain_subseq([1, 2]) == 0
    assert longest_mountain_subseq([1, 2, 3, 4]) == 0
    assert longest_mountain_subseq([4, 3, 2, 1]) == 0


def test_03_bruteforce():
    import itertools
    s = [2, 1, 4, 3]
    best = 0
    for r in range(3, len(s) + 1):
        for idx in itertools.combinations(range(len(s)), r):
            v = [s[i] for i in idx]
            for p in range(1, r - 1):
                up = all(v[k] < v[k + 1] for k in range(p))
                dn = all(v[k] > v[k + 1] for k in range(p, r - 1))
                if up and dn:
                    best = r
                    break
    assert longest_mountain_subseq(s) == best

def test_04_version_and_stdlib_only():
    assert lis_28.LIS_28_VERSION == "lis-28.v1"
    assert lis_28.stdlib_only() is True
