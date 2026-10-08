"""Tests for lis-43 (Count of longest decreasing subsequences)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_43
from lis_43 import count_lds


def test_01_normal_case():
    assert count_lds([3, 2, 2, 1]) == 2
    assert count_lds([5, 4, 3, 2, 1]) == 1
    assert count_lds([4, 3, 2, 1, 2]) == 1


def test_02_edge_cases():
    assert count_lds([]) == 0
    assert count_lds([9]) == 1
    assert count_lds([1, 2, 3]) == 3
    assert count_lds([2, 2, 2]) == 3


def test_03_bruteforce():
    import itertools
    s = [4, 2, 3, 1]
    best, ways = 0, 0
    for r in range(1, len(s) + 1):
        for idx in itertools.combinations(range(len(s)), r):
            v = [s[i] for i in idx]
            if all(v[k] > v[k + 1] for k in range(r - 1)):
                if r > best:
                    best, ways = r, 1
                elif r == best:
                    ways += 1
    assert count_lds(s) == ways

def test_04_version_and_stdlib_only():
    assert lis_43.LIS_43_VERSION == "lis-43.v1"
    assert lis_43.stdlib_only() is True
