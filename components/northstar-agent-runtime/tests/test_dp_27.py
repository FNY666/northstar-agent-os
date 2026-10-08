"""Tests for dp_27 (Best time to buy and sell stock II (many trades))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_27
from dp_27 import max_profit_multi


def test_01_normal_case():
    assert max_profit_multi([7, 1, 5, 3, 6, 4]) == 7
    assert max_profit_multi([1, 2, 3, 4, 5]) == 4


def test_02_edge_cases():
    assert max_profit_multi([]) == 0
    assert max_profit_multi([7, 6, 4, 3, 1]) == 0


def test_03_extra():
    assert max_profit_multi([1, 2, 1, 2, 1, 2]) == 3
    assert max_profit_multi([6, 1, 3, 2, 4, 7]) == 7


def test_04_version_and_stdlib_only():
    assert dp_27.DP_27_VERSION == "dp-27.v1"
    assert dp_27.stdlib_only() is True
