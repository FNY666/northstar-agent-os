"""Tests for dp_28 (Best time to buy and sell stock with cooldown)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_28
from dp_28 import max_profit_cooldown


def test_01_normal_case():
    assert max_profit_cooldown([1, 2, 3, 0, 2]) == 3
    assert max_profit_cooldown([1, 2, 4]) == 3


def test_02_edge_cases():
    assert max_profit_cooldown([]) == 0
    assert max_profit_cooldown([1]) == 0


def test_03_extra():
    assert max_profit_cooldown([6, 1, 3, 2, 4, 7]) == 6
    assert max_profit_cooldown([2, 1, 4]) == 3


def test_04_version_and_stdlib_only():
    assert dp_28.DP_28_VERSION == "dp-28.v1"
    assert dp_28.stdlib_only() is True
