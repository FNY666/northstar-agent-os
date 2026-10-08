"""Tests for lis-22 (LIS via segment tree)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_22
from lis_22 import lis_segtree


def test_01_normal_case():
    assert lis_segtree([10, 9, 2, 5, 3, 7, 101, 18]) == 4
    assert lis_segtree([3, 1, 2]) == 2
    assert lis_segtree([1, 2, 3, 4]) == 4


def test_02_edge_cases():
    assert lis_segtree([]) == 0
    assert lis_segtree([4]) == 1
    assert lis_segtree([2, 2, 2]) == 1
    assert lis_segtree([-2, -2, -1]) == 2


def test_03_matches_quadratic():
    import random
    from lis_01 import lis_length
    random.seed(22)
    for _ in range(15):
        s = [random.randint(-10, 10) for _ in range(40)]
        assert lis_segtree(s) == lis_length(s)

def test_04_version_and_stdlib_only():
    assert lis_22.LIS_22_VERSION == "lis-22.v1"
    assert lis_22.stdlib_only() is True
