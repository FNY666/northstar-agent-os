"""Tests for dp_26 (Best time to buy and sell stock (one trade))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_26
from dp_26 import max_profit_one


def test_01_normal_case():
    assert max_profit_one([7, 1, 5, 3, 6, 4]) == 5
    assert max_profit_one([7, 6, 4, 3, 1]) == 0


def test_02_edge_cases():
    assert max_profit_one([]) == 0
    assert max_profit_one([1]) == 0


def test_03_extra():
    assert max_profit_one([3, 3, 5, 0, 0, 3, 1, 4]) == 4
    assert max_profit_one([2, 4, 1]) == 2


def test_04_version_and_stdlib_only():
    assert dp_26.DP_26_VERSION == "dp-26.v1"
    assert dp_26.stdlib_only() is True
