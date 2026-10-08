"""Tests for lis-07 (Count of longest increasing subsequences)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_07
from lis_07 import count_lis


def test_01_normal_case():
    assert count_lis([1, 3, 5, 4, 7]) == 2
    assert count_lis([1, 2, 4, 3, 5, 4, 7, 2]) == 3
    assert count_lis([1, 2, 3]) == 1


def test_02_edge_cases():
    assert count_lis([]) == 0
    assert count_lis([9]) == 1
    assert count_lis([2, 2, 2, 2, 2]) == 5
    assert count_lis([5, 4, 3, 2, 1]) == 5


def test_03_bruteforce():
    import itertools
    s = [3, 1, 2, 1, 2]
    best = 0
    ways = 0
    for r in range(1, len(s) + 1):
        for idx in itertools.combinations(range(len(s)), r):
            vals = [s[i] for i in idx]
            if all(vals[i] < vals[i + 1] for i in range(len(vals) - 1)):
                if r > best:
                    best, ways = r, 1
                elif r == best:
                    ways += 1
    assert count_lis(s) == ways

def test_04_version_and_stdlib_only():
    assert lis_07.LIS_07_VERSION == "lis-07.v1"
    assert lis_07.stdlib_only() is True
