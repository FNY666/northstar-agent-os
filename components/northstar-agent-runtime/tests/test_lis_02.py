"""Tests for lis-02 (O(n log n) patience-sorting LIS length)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_02
from lis_02 import lis_length_fast


def test_01_normal_case():
    assert lis_length_fast([10, 9, 2, 5, 3, 7, 101, 18]) == 4
    assert lis_length_fast([0, 1, 0, 3, 2, 3]) == 4
    assert lis_length_fast(list(range(1000))) == 1000


def test_02_edge_cases():
    assert lis_length_fast([]) == 0
    assert lis_length_fast([9]) == 1
    assert lis_length_fast([5, 4, 3, 2, 1]) == 1
    assert lis_length_fast([2, 2, 2]) == 1


def test_03_matches_quadratic():
    import random
    random.seed(7)
    for _ in range(20):
        s = [random.randint(0, 20) for _ in range(30)]
        slow = 0
        dp = [1] * len(s)
        for i in range(len(s)):
            for j in range(i):
                if s[j] < s[i] and dp[j] + 1 > dp[i]:
                    dp[i] = dp[j] + 1
        slow = max(dp) if dp else 0
        assert lis_length_fast(s) == slow

def test_04_version_and_stdlib_only():
    assert lis_02.LIS_02_VERSION == "lis-02.v1"
    assert lis_02.stdlib_only() is True
