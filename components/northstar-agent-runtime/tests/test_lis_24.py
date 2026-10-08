"""Tests for lis-24 (Lexicographically smallest LIS)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_24
from lis_24 import smallest_lis


def test_01_normal_case():
    assert smallest_lis([10, 9, 2, 5, 3, 7, 101, 18]) == [2, 3, 7, 18]
    assert smallest_lis([3, 1, 2]) == [1, 2]
    assert smallest_lis([2, 3, 1, 2, 3]) == [1, 2, 3]


def test_02_edge_cases():
    assert smallest_lis([]) == []
    assert smallest_lis([5]) == [5]
    assert smallest_lis([4, 3, 2, 1]) == [1]
    assert smallest_lis([1, 2, 3]) == [1, 2, 3]


def test_03_bruteforce_lex_min():
    import itertools, random
    random.seed(24)
    for _ in range(10):
        s = [random.randint(0, 6) for _ in range(8)]
        cands = []
        for r in range(1, len(s) + 1):
            for idx in itertools.combinations(range(len(s)), r):
                v = [s[i] for i in idx]
                if all(v[k] < v[k + 1] for k in range(r - 1)):
                    cands.append(v)
        best_len = max(len(v) for v in cands)
        expect = min(v for v in cands if len(v) == best_len)
        assert smallest_lis(s) == expect

def test_04_version_and_stdlib_only():
    assert lis_24.LIS_24_VERSION == "lis-24.v1"
    assert lis_24.stdlib_only() is True
