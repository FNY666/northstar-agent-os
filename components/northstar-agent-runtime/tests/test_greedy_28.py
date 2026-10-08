"""Tests for greedy_28 (Maximum units on a truck)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_28
from greedy_28 import max_units_truck


def test_01_normal_case():
    assert max_units_truck([[1, 3], [2, 2], [3, 1]], 4) == 8
    assert max_units_truck([[5, 10], [2, 5], [4, 7], [3, 9]], 10) == 91


def test_02_edge_cases():
    assert max_units_truck([], 5) == 0
    assert max_units_truck([[1, 3]], 0) == 0


def test_03_extra():
    assert max_units_truck([[2, 1]], 5) == 2
    assert max_units_truck([[3, 4], [1, 10]], 2) == 14


def test_04_version_and_stdlib_only():
    assert greedy_28.GREEDY_28_VERSION == "greedy-28.v1"
    assert greedy_28.stdlib_only() is True
