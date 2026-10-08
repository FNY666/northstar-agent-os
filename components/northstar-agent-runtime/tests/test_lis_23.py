"""Tests for lis-23 (Count of all strictly increasing subsequences)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_23
from lis_23 import count_increasing_subseqs


def test_01_normal_case():
    assert count_increasing_subseqs([1, 2, 3]) == 7
    assert count_increasing_subseqs([1, 2, 3, 4]) == 15
    assert count_increasing_subseqs([2, 1, 3]) == 5


def test_02_edge_cases():
    assert count_increasing_subseqs([]) == 0
    assert count_increasing_subseqs([5]) == 1
    assert count_increasing_subseqs([3, 2, 1]) == 3
    assert count_increasing_subseqs([1, 1, 1]) == 3


def test_03_bruteforce():
    import itertools
    s = [3, 1, 4, 2]
    total = 0
    for r in range(1, len(s) + 1):
        for idx in itertools.combinations(range(len(s)), r):
            if all(s[idx[k]] < s[idx[k + 1]] for k in range(r - 1)):
                total += 1
    assert count_increasing_subseqs(s) == total

def test_04_version_and_stdlib_only():
    assert lis_23.LIS_23_VERSION == "lis-23.v1"
    assert lis_23.stdlib_only() is True
