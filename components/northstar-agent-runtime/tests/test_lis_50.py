"""Tests for lis-50 (Maximum sum increasing subsequence with path)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_50
from lis_50 import max_sum_increasing_with_path


def test_01_normal_case():
    s, p = max_sum_increasing_with_path([1, 101, 2, 3, 100, 4, 5])
    assert s == 106
    assert p == [1, 2, 3, 100]
    s2, p2 = max_sum_increasing_with_path([10, 5, 4, 3])
    assert s2 == 10 and p2 == [10]


def test_02_edge_cases():
    assert max_sum_increasing_with_path([]) == (0, [])
    s, p = max_sum_increasing_with_path([7])
    assert (s, p) == (7, [7])
    s, p = max_sum_increasing_with_path([-5, -2, -8])
    assert s == -2 and p == [-2]


def test_03_path_valid():
    s = [3, 2, 6, 4, 5, 1]
    total, path = max_sum_increasing_with_path(s)
    assert sum(path) == total
    assert all(path[i] < path[i + 1] for i in range(len(path) - 1))
    idx = -1
    for v in path:
        idx = s.index(v, idx + 1)

def test_04_version_and_stdlib_only():
    assert lis_50.LIS_50_VERSION == "lis-50.v1"
    assert lis_50.stdlib_only() is True
