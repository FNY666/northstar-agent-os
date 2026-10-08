"""Tests for lis-42 (Patience-sorting tails array)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_42
from lis_42 import patience_tails


def test_01_normal_case():
    assert patience_tails([10, 9, 2, 5, 3, 7, 101, 18]) == [2, 3, 7, 18]
    assert patience_tails([3, 1, 2]) == [1, 2]
    assert patience_tails([1, 2, 3]) == [1, 2, 3]


def test_02_edge_cases():
    assert patience_tails([]) == []
    assert patience_tails([5]) == [5]
    assert patience_tails([2, 2, 2]) == [2]


def test_03_length_matches():
    from lis_02 import lis_length_fast
    import random
    random.seed(42)
    for _ in range(10):
        s = [random.randint(0, 9) for _ in range(15)]
        assert len(patience_tails(s)) == lis_length_fast(s)

def test_04_version_and_stdlib_only():
    assert lis_42.LIS_42_VERSION == "lis-42.v1"
    assert lis_42.stdlib_only() is True
