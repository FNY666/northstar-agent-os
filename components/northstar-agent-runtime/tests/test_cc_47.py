"""Tests for cc_47 (Minimum coins with exactly one large coin)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_47
from cc_47 import min_coins_one_large


def test_01_normal_case():
    assert min_coins_one_large(11, [1, 2, 5], 2) == 3
    assert min_coins_one_large(10, [1, 2, 5], 4) == 2


def test_02_edge_cases():
    assert min_coins_one_large(4, [1, 2, 5], 2) == -1
    assert min_coins_one_large(0, [1, 5], 2) == -1


def test_03_extra():
    try:
        min_coins_one_large(-1, [1], 0)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins_one_large(6, [1, 3, 4], 2) == 2


def test_04_version_and_stdlib_only():
    assert cc_47.CC_47_VERSION == "cc-47.v1"
    assert cc_47.stdlib_only() is True
