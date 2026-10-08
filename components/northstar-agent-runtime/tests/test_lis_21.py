"""Tests for lis-21 (LIS via Fenwick tree)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_21
from lis_21 import lis_fenwick


def test_01_normal_case():
    assert lis_fenwick([10, 9, 2, 5, 3, 7, 101, 18]) == 4
    assert lis_fenwick([0, 8, 4, 12, 2, 10, 6, 14, 1, 9]) == 4
    assert lis_fenwick([1, 2, 3, 4, 5]) == 5


def test_02_edge_cases():
    assert lis_fenwick([]) == 0
    assert lis_fenwick([3]) == 1
    assert lis_fenwick([2, 2, 2]) == 1
    assert lis_fenwick([-5, -1, -3, 0, 2]) == 4


def test_03_matches_quadratic():
    import random
    from lis_01 import lis_length
    random.seed(21)
    for _ in range(15):
        s = [random.randint(-10, 10) for _ in range(40)]
        assert lis_fenwick(s) == lis_length(s)

def test_04_version_and_stdlib_only():
    assert lis_21.LIS_21_VERSION == "lis-21.v1"
    assert lis_21.stdlib_only() is True
