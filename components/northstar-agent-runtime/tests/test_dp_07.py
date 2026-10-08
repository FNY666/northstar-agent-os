"""Tests for dp_07 (0/1 knapsack)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_07
from dp_07 import knapsack


def test_01_normal_case():
    assert knapsack([1, 2, 3], [6, 10, 12], 5) == 22
    assert knapsack([2, 3, 4], [3, 4, 5], 5) == 7


def test_02_edge_cases():
    assert knapsack([1, 2, 3], [6, 10, 12], 0) == 0
    assert knapsack([], [], 10) == 0


def test_03_extra():
    assert knapsack([5], [10], 4) == 0
    assert knapsack([5], [10], 5) == 10
    try:
        knapsack([1], [2], -1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert dp_07.DP_07_VERSION == "dp-07.v1"
    assert dp_07.stdlib_only() is True
