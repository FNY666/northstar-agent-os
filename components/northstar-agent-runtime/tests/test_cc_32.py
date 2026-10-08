"""Tests for cc_32 (Square denominations)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_32
from cc_32 import square_denominations, min_coins_squares


def test_01_normal_case():
    assert square_denominations(10) == [1, 4, 9]
    assert min_coins_squares(12) == 3
    assert min_coins_squares(13) == 2


def test_02_edge_cases():
    assert square_denominations(0) == []
    assert min_coins_squares(0) == 0
    assert min_coins_squares(1) == 1


def test_03_extra():
    try:
        min_coins_squares(-2)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # Lagrange: every positive integer is a sum of at most 4 squares
    assert all(min_coins_squares(a) <= 4 for a in range(1, 50))


def test_04_version_and_stdlib_only():
    assert cc_32.CC_32_VERSION == "cc-32.v1"
    assert cc_32.stdlib_only() is True
