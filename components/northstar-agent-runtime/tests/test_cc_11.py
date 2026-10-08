"""Tests for cc_11 (Minimum coins with reconstruction)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_11
from cc_11 import min_coins_with_change


def test_01_normal_case():
    assert min_coins_with_change(11, [1, 2, 5]) == (3, [1, 5, 5])
    count, used = min_coins_with_change(6, [1, 3, 4])
    assert count == 2 and sum(used) == 6


def test_02_edge_cases():
    assert min_coins_with_change(0, [1, 2]) == (0, [])
    assert min_coins_with_change(3, [2]) == (-1, [])


def test_03_extra():
    try:
        min_coins_with_change(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    count, used = min_coins_with_change(27, [1, 2, 5, 10])
    assert count == 4 and sum(used) == 27


def test_04_version_and_stdlib_only():
    assert cc_11.CC_11_VERSION == "cc-11.v1"
    assert cc_11.stdlib_only() is True
