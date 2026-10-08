"""Tests for dp_06 (Coin change II (number of ways))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_06
from dp_06 import change_ways


def test_01_normal_case():
    assert change_ways([1, 2, 5], 5) == 4
    assert change_ways([2, 3, 5], 8) == 3


def test_02_edge_cases():
    assert change_ways([1], 0) == 1
    assert change_ways([], 3) == 0


def test_03_extra():
    assert change_ways([1, 2, 3], 4) == 4
    try:
        change_ways([1], -1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert dp_06.DP_06_VERSION == "dp-06.v1"
    assert dp_06.stdlib_only() is True
