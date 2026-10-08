"""Tests for greedy_16 (Best time to buy and sell stock II)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_16
from greedy_16 import max_profit_ii


def test_01_normal_case():
    assert max_profit_ii([7, 1, 5, 3, 6, 4]) == 7
    assert max_profit_ii([1, 2, 3, 4, 5]) == 4


def test_02_edge_cases():
    assert max_profit_ii([]) == 0
    assert max_profit_ii([5]) == 0


def test_03_extra():
    assert max_profit_ii([7, 6, 4, 3, 1]) == 0
    assert max_profit_ii([3, 3, 3]) == 0


def test_04_version_and_stdlib_only():
    assert greedy_16.GREEDY_16_VERSION == "greedy-16.v1"
    assert greedy_16.stdlib_only() is True
