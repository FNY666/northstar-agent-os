"""Tests for cc_42 (Count ways using at most m denominations)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_42
from cc_42 import count_ways_at_most_m_denoms


def test_01_normal_case():
    assert count_ways_at_most_m_denoms(5, [1, 2, 5], 1) == 2
    assert count_ways_at_most_m_denoms(5, [1, 2, 5], 2) == 4


def test_02_edge_cases():
    assert count_ways_at_most_m_denoms(0, [1, 2], 1) == 1
    assert count_ways_at_most_m_denoms(5, [1, 2, 5], 0) == 0


def test_03_extra():
    try:
        count_ways_at_most_m_denoms(-1, [1], 1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # m large enough to cover every combination
    assert count_ways_at_most_m_denoms(5, [1, 2, 5], 3) == 4


def test_04_version_and_stdlib_only():
    assert cc_42.CC_42_VERSION == "cc-42.v1"
    assert cc_42.stdlib_only() is True
