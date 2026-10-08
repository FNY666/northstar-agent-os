"""Tests for lis-10 (Maximum sum increasing subsequence)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_10
from lis_10 import max_sum_increasing


def test_01_normal_case():
    assert max_sum_increasing([1, 101, 2, 3, 100, 4, 5]) == 106
    assert max_sum_increasing([10, 5, 4, 3]) == 10
    assert max_sum_increasing([3, 2, 6, 4, 5, 1]) == 12


def test_02_edge_cases():
    assert max_sum_increasing([]) == 0
    assert max_sum_increasing([7]) == 7
    assert max_sum_increasing([-5, -2, -8, -1]) == -1
    assert max_sum_increasing([1, 2, 3]) == 6


def test_03_bruteforce():
    import itertools
    s = [4, 1, 3, 2, 5]
    best = max(
        sum(s[i] for i in idx)
        for r in range(1, len(s) + 1)
        for idx in itertools.combinations(range(len(s)), r)
        if all(s[idx[k]] < s[idx[k + 1]] for k in range(len(idx) - 1))
    )
    assert max_sum_increasing(s) == best

def test_04_version_and_stdlib_only():
    assert lis_10.LIS_10_VERSION == "lis-10.v1"
    assert lis_10.stdlib_only() is True
