"""Tests for cc_19 (Minimum coins with parity constraint)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_19
from cc_19 import min_coins_with_parity


def test_01_normal_case():
    assert min_coins_with_parity(11, [1, 2, 5], 1) == 3
    assert min_coins_with_parity(10, [1, 2, 5], 0) == 2


def test_02_edge_cases():
    assert min_coins_with_parity(0, [1, 2], 0) == 0
    assert min_coins_with_parity(0, [1, 2], 1) == -1
    assert min_coins_with_parity(3, [2], 0) == -1


def test_03_extra():
    try:
        min_coins_with_parity(5, [1], 2)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins_with_parity(6, [1, 3, 4], 0) == 2


def test_04_version_and_stdlib_only():
    assert cc_19.CC_19_VERSION == "cc-19.v1"
    assert cc_19.stdlib_only() is True
