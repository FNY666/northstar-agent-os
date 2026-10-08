"""Tests for dp_05 (Coin change (minimum coins))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_05
from dp_05 import coin_change


def test_01_normal_case():
    assert coin_change([1, 2, 5], 11) == 3
    assert coin_change([186, 419, 83, 408], 6249) == 20


def test_02_edge_cases():
    assert coin_change([2], 3) == -1
    assert coin_change([1], 0) == 0


def test_03_extra():
    assert coin_change([2, 5, 10, 1], 27) == 4
    try:
        coin_change([1], -2)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert dp_05.DP_05_VERSION == "dp-05.v1"
    assert dp_05.stdlib_only() is True
