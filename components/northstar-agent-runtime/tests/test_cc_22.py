"""Tests for cc_22 (Arithmetic-progression denominations)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_22
from cc_22 import arithmetic_denominations, min_coins_arith


def test_01_normal_case():
    assert arithmetic_denominations(1, 2, 4) == [1, 3, 5, 7]
    assert min_coins_arith(11, 1, 2, 4) == 3


def test_02_edge_cases():
    assert arithmetic_denominations(5, 5, 0) == []
    assert min_coins_arith(0, 1, 1, 3) == 0
    assert min_coins_arith(3, 2, 2, 2) == -1


def test_03_extra():
    try:
        arithmetic_denominations(1, 0, 3)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins_arith(10, 5, 5, 3) == 1


def test_04_version_and_stdlib_only():
    assert cc_22.CC_22_VERSION == "cc-22.v1"
    assert cc_22.stdlib_only() is True
