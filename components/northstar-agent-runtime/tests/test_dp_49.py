"""Tests for dp_49 (Dungeon game (minimum HP))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_49
from dp_49 import dungeon


def test_01_normal_case():
    assert dungeon([[-2, -3, 3], [-5, -10, 1], [10, 30, -5]]) == 7
    assert dungeon([[1, -3, 3], [0, -2, 0], [-3, -3, -3]]) == 3


def test_02_edge_cases():
    assert dungeon([[0]]) == 1
    try:
        dungeon([[]])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_03_extra():
    assert dungeon([[-3]]) == 4
    assert dungeon([[2, 2], [2, 2]]) == 1


def test_04_version_and_stdlib_only():
    assert dp_49.DP_49_VERSION == "dp-49.v1"
    assert dp_49.stdlib_only() is True
