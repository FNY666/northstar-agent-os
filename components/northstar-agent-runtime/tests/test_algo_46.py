"""Tests for algo_46: coin change (minimum coins)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import algo_46 as a46
from algo_46 import coin_change


def test_version_pin_and_stdlib_only():
    assert a46.ALGO_46_VERSION == "algo-46.v1"
    assert a46.stdlib_only() is True


def test_coin_change_classic():
    assert coin_change([1, 2, 5], 11) == 3  # 5 + 5 + 1


def test_coin_change_impossible_and_zero():
    assert coin_change([2], 3) == -1
    assert coin_change([], 7) == -1
    assert coin_change([1], 0) == 0
    assert coin_change([], 0) == 0
    assert coin_change([5], 5) == 1


def test_coin_change_rejects_bad_input():
    with pytest.raises(ValueError):
        coin_change([1, 2, 5], -3)
    with pytest.raises(ValueError):
        coin_change([1, 0], 5)
    with pytest.raises(ValueError):
        coin_change([-2], 5)
