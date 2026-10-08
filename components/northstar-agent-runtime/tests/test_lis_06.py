"""Tests for lis-06 (Longest non-increasing subsequence)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_06
from lis_06 import lnis_length


def test_01_normal_case():
    assert lnis_length([3, 2, 2, 1]) == 4
    assert lnis_length([5, 4, 4, 3, 3, 1]) == 6
    assert lnis_length([4, 4, 4]) == 3


def test_02_edge_cases():
    assert lnis_length([]) == 0
    assert lnis_length([6]) == 1
    assert lnis_length([1, 2, 3, 4]) == 1


def test_03_matches_bruteforce():
    import random
    random.seed(11)
    from lis_05 import lds_length
    for _ in range(15):
        s = [random.randint(0, 9) for _ in range(20)]
        n = len(s)
        dp = [1] * n
        for i in range(n):
            for j in range(i):
                if s[j] >= s[i] and dp[j] + 1 > dp[i]:
                    dp[i] = dp[j] + 1
        assert lnis_length(s) == (max(dp) if dp else 0)

def test_04_version_and_stdlib_only():
    assert lis_06.LIS_06_VERSION == "lis-06.v1"
    assert lis_06.stdlib_only() is True
