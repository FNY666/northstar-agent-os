"""Tests for lis-17 (Longest pair chain)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_17
from lis_17 import longest_pair_chain


def test_01_normal_case():
    assert longest_pair_chain([[1, 2], [2, 3], [3, 4]]) == 2
    assert longest_pair_chain([[1, 2], [7, 8], [4, 5]]) == 3
    assert longest_pair_chain([[3, 4], [2, 3], [1, 2]]) == 2


def test_02_edge_cases():
    assert longest_pair_chain([]) == 0
    assert longest_pair_chain([[0, 1]]) == 1
    assert longest_pair_chain([[1, 10], [2, 3], [4, 5]]) == 2


def test_03_greedy_optimal():
    import itertools
    ps = [[1, 2], [2, 3], [3, 4], [1, 3]]
    best = 0
    for r in range(1, len(ps) + 1):
        for idx in itertools.permutations(range(len(ps)), r):
            ok = all(ps[idx[k]][1] < ps[idx[k + 1]][0] for k in range(r - 1))
            if ok:
                best = max(best, r)
    assert longest_pair_chain(ps) == best

def test_04_version_and_stdlib_only():
    assert lis_17.LIS_17_VERSION == "lis-17.v1"
    assert lis_17.stdlib_only() is True
