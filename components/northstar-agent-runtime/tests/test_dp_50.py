"""Tests for dp_50 (Number of dice rolls with target sum)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_50
from dp_50 import dice_rolls


def test_01_normal_case():
    assert dice_rolls(1, 6, 3) == 1
    assert dice_rolls(2, 6, 7) == 6


def test_02_edge_cases():
    assert dice_rolls(2, 6, 1) == 0
    assert dice_rolls(3, 6, 3) == 1


def test_03_extra():
    assert dice_rolls(2, 6, 12) == 1
    assert dice_rolls(30, 30, 500) == 222616187
    try:
        dice_rolls(2, 0, 5)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert dp_50.DP_50_VERSION == "dp-50.v1"
    assert dp_50.stdlib_only() is True
