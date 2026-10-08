"""Tests for cc_36 (Minimum coins with mandatory denomination)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_36
from cc_36 import min_coins_mandatory


def test_01_normal_case():
    assert min_coins_mandatory(11, [1, 2, 5], 5) == 3
    assert min_coins_mandatory(10, [1, 2, 5], 2) == 4


def test_02_edge_cases():
    assert min_coins_mandatory(3, [1, 2, 5], 5) == -1
    assert min_coins_mandatory(0, [1, 2], 1) == -1


def test_03_extra():
    try:
        min_coins_mandatory(10, [1, 2], 5)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins_mandatory(6, [1, 3, 4], 4) == 3


def test_04_version_and_stdlib_only():
    assert cc_36.CC_36_VERSION == "cc-36.v1"
    assert cc_36.stdlib_only() is True
