"""Tests for cc_35 (Triangular denominations)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_35
from cc_35 import triangular_denominations, min_coins_triangular


def test_01_normal_case():
    assert triangular_denominations(10) == [1, 3, 6, 10]
    assert min_coins_triangular(11) == 2
    assert min_coins_triangular(12) == 2


def test_02_edge_cases():
    assert triangular_denominations(0) == []
    assert min_coins_triangular(0) == 0
    assert min_coins_triangular(2) == 2


def test_03_extra():
    try:
        min_coins_triangular(-1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins_triangular(28) == 1


def test_04_version_and_stdlib_only():
    assert cc_35.CC_35_VERSION == "cc-35.v1"
    assert cc_35.stdlib_only() is True
