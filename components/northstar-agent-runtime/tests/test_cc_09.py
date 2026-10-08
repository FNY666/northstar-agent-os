"""Tests for cc_09 (Minimum coins (0/1, each coin used at most once))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_09
from cc_09 import min_coins_01


def test_01_normal_case():
    assert min_coins_01(8, [1, 2, 5, 10]) == 3
    assert min_coins_01(15, [1, 2, 5, 10]) == 2


def test_02_edge_cases():
    assert min_coins_01(0, [5]) == 0
    assert min_coins_01(9, [1, 2, 5, 10]) == -1
    assert min_coins_01(3, [5]) == -1


def test_03_extra():
    try:
        min_coins_01(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # duplicate values are distinct usable coins here
    assert min_coins_01(2, [1, 1, 5]) == 2


def test_04_version_and_stdlib_only():
    assert cc_09.CC_09_VERSION == "cc-09.v1"
    assert cc_09.stdlib_only() is True
