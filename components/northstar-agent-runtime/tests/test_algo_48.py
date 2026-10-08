"""Tests for algo_48: rod cutting (maximum revenue)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import algo_48 as a48
from algo_48 import rod_cutting

PRICES = [1, 5, 8, 9, 10, 17, 17, 20]


def test_version_pin_and_stdlib_only():
    assert a48.ALGO_48_VERSION == "algo-48.v1"
    assert a48.stdlib_only() is True


def test_rod_cutting_classic():
    assert rod_cutting(PRICES, 4) == 10  # 2 + 2
    assert rod_cutting(PRICES, 8) == 22  # 2 + 6


def test_rod_cutting_edge_cases():
    assert rod_cutting(PRICES, 0) == 0
    assert rod_cutting([], 5) == 0
    assert rod_cutting([5], 1) == 5
    assert rod_cutting([5], 3) == 15  # three pieces of length 1
    assert rod_cutting(PRICES, 1) == 1


def test_rod_cutting_rejects_negative_n():
    with pytest.raises(ValueError):
        rod_cutting(PRICES, -2)
