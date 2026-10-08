"""Tests for algo_42: 0/1 knapsack."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import algo_42 as a42
from algo_42 import knapsack


def test_version_pin_and_stdlib_only():
    assert a42.ALGO_42_VERSION == "algo-42.v1"
    assert a42.stdlib_only() is True


def test_knapsack_classic():
    # weights=[1,3,4,5], values=[1,4,5,7], capacity=7 -> pick 3+4, value 4+5=9
    assert knapsack([1, 3, 4, 5], [1, 4, 5, 7], 7) == 9


def test_knapsack_edge_cases():
    assert knapsack([], [], 10) == 0
    assert knapsack([1, 2], [3, 4], 0) == 0
    assert knapsack([5], [10], 3) == 0  # single item too heavy
    assert knapsack([1, 2], [3, 4], 10) == 7  # everything fits


def test_knapsack_rejects_bad_input():
    with pytest.raises(ValueError):
        knapsack([1], [1], -1)
    with pytest.raises(ValueError):
        knapsack([1, 2], [3], 5)
    with pytest.raises(ValueError):
        knapsack([-1], [3], 5)
