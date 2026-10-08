"""Tests for dp_41 (Stone game (optimal play))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_41
from dp_41 import stone_game


def test_01_normal_case():
    assert stone_game([5, 3, 4, 5]) is True
    assert stone_game([3, 7, 2, 3]) is True


def test_02_edge_cases():
    assert stone_game([]) is False
    assert stone_game([1, 2]) is True


def test_03_extra():
    assert stone_game([1, 100, 3]) is False
    assert stone_game([8, 15, 3, 7]) is True


def test_04_version_and_stdlib_only():
    assert dp_41.DP_41_VERSION == "dp-41.v1"
    assert dp_41.stdlib_only() is True
