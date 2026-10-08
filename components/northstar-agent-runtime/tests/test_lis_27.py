"""Tests for lis-27 (Decision: increasing run of length K (fast))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_27
from lis_27 import has_increasing_subseq_len


def test_01_normal_case():
    assert has_increasing_subseq_len([3, 1, 2], 2) is True
    assert has_increasing_subseq_len([3, 1, 2], 3) is False
    assert has_increasing_subseq_len([1, 2, 3, 4], 4) is True


def test_02_edge_cases():
    assert has_increasing_subseq_len([], 0) is True
    assert has_increasing_subseq_len([], 1) is False
    assert has_increasing_subseq_len([5], 1) is True
    assert has_increasing_subseq_len([5], 2) is False


def test_03_matches_quadratic():
    from lis_18 import has_lis_of_length
    import random
    random.seed(27)
    for _ in range(10):
        s = [random.randint(0, 9) for _ in range(15)]
        for k in (0, 1, 3, 7):
            assert has_increasing_subseq_len(s, k) == has_lis_of_length(s, k)

def test_04_version_and_stdlib_only():
    assert lis_27.LIS_27_VERSION == "lis-27.v1"
    assert lis_27.stdlib_only() is True
