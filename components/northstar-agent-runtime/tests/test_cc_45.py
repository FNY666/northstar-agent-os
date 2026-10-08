"""Tests for cc_45 (Minimum coins using every denomination)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_45
from cc_45 import min_coins_use_all


def test_01_normal_case():
    assert min_coins_use_all(11, [1, 2, 5]) == 5
    assert min_coins_use_all(8, [1, 2, 5]) == 3


def test_02_edge_cases():
    assert min_coins_use_all(7, [1, 2, 5]) == -1
    assert min_coins_use_all(0, [1, 2]) == -1


def test_03_extra():
    try:
        min_coins_use_all(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins_use_all(10, [2, 3]) == 4


def test_04_version_and_stdlib_only():
    assert cc_45.CC_45_VERSION == "cc-45.v1"
    assert cc_45.stdlib_only() is True
