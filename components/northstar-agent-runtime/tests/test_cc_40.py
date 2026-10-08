"""Tests for cc_40 (Minimum-coins table)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_40
from cc_40 import min_coins_table


def test_01_normal_case():
    assert min_coins_table(6, [1, 3, 4]) == [0, 1, 2, 1, 1, 2, 2]
    assert min_coins_table(5, [1, 2, 5]) == [0, 1, 1, 2, 2, 1]


def test_02_edge_cases():
    assert min_coins_table(0, [5]) == [0]
    assert min_coins_table(3, [2]) == [0, -1, 1, -1]


def test_03_extra():
    try:
        min_coins_table(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    table = min_coins_table(27, [1, 2, 5, 10])
    assert table[27] == 4 and table[0] == 0


def test_04_version_and_stdlib_only():
    assert cc_40.CC_40_VERSION == "cc-40.v1"
    assert cc_40.stdlib_only() is True
