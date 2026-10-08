"""Tests for lis-44 (Longest even/odd alternating subsequence)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_44
from lis_44 import longest_parity_alternating


def test_01_normal_case():
    assert longest_parity_alternating([1, 2, 3, 4]) == 4
    assert longest_parity_alternating([1, 3, 2, 4, 6]) == 3
    assert longest_parity_alternating([2, 1, 4, 3]) == 4


def test_02_edge_cases():
    assert longest_parity_alternating([]) == 0
    assert longest_parity_alternating([5]) == 1
    assert longest_parity_alternating([2, 4, 6]) == 1
    assert longest_parity_alternating([1, 3, 5]) == 1


def test_03_bruteforce():
    import itertools
    s = [1, 2, 4, 3]
    best = 1 if s else 0
    for r in range(2, len(s) + 1):
        for idx in itertools.combinations(range(len(s)), r):
            v = [s[i] for i in idx]
            if all(v[k] % 2 != v[k + 1] % 2 for k in range(r - 1)):
                best = r
    assert longest_parity_alternating(s) == best

def test_04_version_and_stdlib_only():
    assert lis_44.LIS_44_VERSION == "lis-44.v1"
    assert lis_44.stdlib_only() is True
