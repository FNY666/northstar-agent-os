"""Tests for cc_39 (Minimum coins with large-denomination penalty)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_39
from cc_39 import min_coins_penalty


def test_01_normal_case():
    assert min_coins_penalty(11, [1, 2, 5], 2, 10) == 11
    assert min_coins_penalty(11, [1, 2, 5], 2, 0) == 3


def test_02_edge_cases():
    assert min_coins_penalty(0, [1, 2], 1, 5) == 0
    assert min_coins_penalty(3, [2], 1, 5) == -1


def test_03_extra():
    try:
        min_coins_penalty(-1, [1], 1, 1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # penalty 1 on large coins: 5+5+1 -> 3 + 2 = 5 vs eleven 1s -> 11
    assert min_coins_penalty(11, [1, 2, 5], 2, 1) == 5


def test_04_version_and_stdlib_only():
    assert cc_39.CC_39_VERSION == "cc-39.v1"
    assert cc_39.stdlib_only() is True
