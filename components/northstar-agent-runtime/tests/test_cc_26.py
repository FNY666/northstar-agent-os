"""Tests for cc_26 (Minimum coins under a weight budget)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_26
from cc_26 import min_coins_weight_budget


def test_01_normal_case():
    assert min_coins_weight_budget(11, {1: 1, 2: 3, 5: 2}, 6) == 3
    assert min_coins_weight_budget(10, {2: 1, 5: 1}, 10) == 2


def test_02_edge_cases():
    assert min_coins_weight_budget(0, {1: 1}, 0) == 0
    assert min_coins_weight_budget(11, {1: 1, 2: 3, 5: 2}, 4) == -1


def test_03_extra():
    try:
        min_coins_weight_budget(-1, {1: 1}, 5)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # generous budget behaves like the unconstrained problem
    assert min_coins_weight_budget(11, {1: 1, 2: 1, 5: 1}, 100) == 3


def test_04_version_and_stdlib_only():
    assert cc_26.CC_26_VERSION == "cc-26.v1"
    assert cc_26.stdlib_only() is True
