"""Tests for cc_41 (Minimum coins using at most m denominations)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_41
from cc_41 import min_coins_at_most_m_denoms


def test_01_normal_case():
    assert min_coins_at_most_m_denoms(11, [1, 2, 5], 1) == 11
    assert min_coins_at_most_m_denoms(11, [1, 2, 5], 2) == 3


def test_02_edge_cases():
    assert min_coins_at_most_m_denoms(0, [1, 2], 0) == 0
    assert min_coins_at_most_m_denoms(5, [2], 1) == -1
    assert min_coins_at_most_m_denoms(5, [1, 2, 5], 0) == -1


def test_03_extra():
    try:
        min_coins_at_most_m_denoms(-1, [1], 1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins_at_most_m_denoms(11, [1, 2, 5], 3) == 3


def test_04_version_and_stdlib_only():
    assert cc_41.CC_41_VERSION == "cc-41.v1"
    assert cc_41.stdlib_only() is True
