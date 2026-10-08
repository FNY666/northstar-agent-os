"""Tests for greedy_46 (Minimum cost to move chips)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_46
from greedy_46 import min_cost_move_chips


def test_01_normal_case():
    assert min_cost_move_chips([1, 2, 3]) == 1
    assert min_cost_move_chips([2, 2, 2, 3, 3]) == 2


def test_02_edge_cases():
    assert min_cost_move_chips([]) == 0
    assert min_cost_move_chips([4]) == 0


def test_03_extra():
    assert min_cost_move_chips([1, 3, 5]) == 0
    assert min_cost_move_chips([1, 1000000000]) == 1


def test_04_version_and_stdlib_only():
    assert greedy_46.GREEDY_46_VERSION == "greedy-46.v1"
    assert greedy_46.stdlib_only() is True
