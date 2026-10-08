"""Tests for cc_13 (Minimum coins to reach at least target)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_13
from cc_13 import min_coins_at_least


def test_01_normal_case():
    assert min_coins_at_least(11, [5, 10]) == (2, 15)
    assert min_coins_at_least(9, [5, 10]) == (1, 10)


def test_02_edge_cases():
    assert min_coins_at_least(0, [5]) == (0, 0)
    assert min_coins_at_least(10, [5, 10]) == (1, 10)


def test_03_extra():
    try:
        min_coins_at_least(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    count, reached = min_coins_at_least(14, [5, 10])
    assert count == 2 and reached == 15


def test_04_version_and_stdlib_only():
    assert cc_13.CC_13_VERSION == "cc-13.v1"
    assert cc_13.stdlib_only() is True
