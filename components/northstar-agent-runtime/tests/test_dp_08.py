"""Tests for dp_08 (Unbounded knapsack)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_08
from dp_08 import unbounded_knapsack


def test_01_normal_case():
    assert unbounded_knapsack([1, 2, 3], [1, 5, 8], 4) == 10
    assert unbounded_knapsack([2, 3], [3, 5], 7) == 11


def test_02_edge_cases():
    assert unbounded_knapsack([2], [3], 1) == 0
    assert unbounded_knapsack([1], [7], 0) == 0


def test_03_extra():
    assert unbounded_knapsack([3, 4, 5], [30, 50, 60], 8) == 100
    try:
        unbounded_knapsack([1], [2], -1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert dp_08.DP_08_VERSION == "dp-08.v1"
    assert dp_08.stdlib_only() is True
