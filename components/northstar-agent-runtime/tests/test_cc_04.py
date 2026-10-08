"""Tests for cc_04 (Minimum coins (bounded supply))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_04
from cc_04 import min_coins_bounded


def test_01_normal_case():
    assert min_coins_bounded(11, [(5, 2), (2, 3), (1, 5)]) == 3
    assert min_coins_bounded(6, [(4, 1), (1, 10)]) == 3


def test_02_edge_cases():
    assert min_coins_bounded(0, [(5, 1)]) == 0
    assert min_coins_bounded(11, [(5, 1), (2, 1)]) == -1
    assert min_coins_bounded(5, []) == -1


def test_03_extra():
    try:
        min_coins_bounded(-1, [(1, 2)])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    try:
        min_coins_bounded(5, [(0, 2)])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins_bounded(30, [(25, 1), (10, 3)]) == 3


def test_04_version_and_stdlib_only():
    assert cc_04.CC_04_VERSION == "cc-04.v1"
    assert cc_04.stdlib_only() is True
