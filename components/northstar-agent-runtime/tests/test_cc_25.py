"""Tests for cc_25 (Robust min coins (worst single-denomination removal))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_25
from cc_25 import min_coins_robust


def test_01_normal_case():
    assert min_coins_robust(11, [1, 2, 5]) == 6
    # remove 5 -> {1,2}: five 2s = 5 coins is the worst case
    assert min_coins_robust(10, [1, 2, 5]) == 5


def test_02_edge_cases():
    assert min_coins_robust(0, [1, 2]) == 0
    # removing 2 leaves {3}, which cannot make 5
    assert min_coins_robust(5, [2, 3]) == -1


def test_03_extra():
    try:
        min_coins_robust(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins_robust(6, [1, 3, 4]) == 3


def test_04_version_and_stdlib_only():
    assert cc_25.CC_25_VERSION == "cc-25.v1"
    assert cc_25.stdlib_only() is True
