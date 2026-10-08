"""Tests for greedy_17 (Best time to buy and sell stock I)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_17
from greedy_17 import max_profit_i


def test_01_normal_case():
    assert max_profit_i([7, 1, 5, 3, 6, 4]) == 5
    assert max_profit_i([2, 4, 1]) == 2


def test_02_edge_cases():
    assert max_profit_i([]) == 0
    assert max_profit_i([5]) == 0


def test_03_extra():
    assert max_profit_i([7, 6, 4, 3, 1]) == 0
    assert max_profit_i([1, 2]) == 1


def test_04_version_and_stdlib_only():
    assert greedy_17.GREEDY_17_VERSION == "greedy-17.v1"
    assert greedy_17.stdlib_only() is True
