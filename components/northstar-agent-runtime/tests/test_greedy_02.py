"""Tests for greedy_02 (Fractional knapsack)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_02
from greedy_02 import fractional_knapsack


def test_01_normal_case():
    assert fractional_knapsack([(60, 10), (100, 20), (120, 30)], 50) == 240.0


def test_02_edge_cases():
    assert fractional_knapsack([], 10) == 0.0
    assert fractional_knapsack([(60, 10)], 0) == 0.0


def test_03_extra():
    assert abs(fractional_knapsack([(60, 10), (100, 20)], 15) - 85.0) < 1e-9
    assert fractional_knapsack([(10, 5)], 100) == 10.0


def test_04_version_and_stdlib_only():
    assert greedy_02.GREEDY_02_VERSION == "greedy-02.v1"
    assert greedy_02.stdlib_only() is True
