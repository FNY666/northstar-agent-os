"""Tests for cc_16 (Count ways with exactly k coins)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_16
from cc_16 import count_ways_exact_k


def test_01_normal_case():
    assert count_ways_exact_k(5, [1, 2, 5], 3) == 1
    assert count_ways_exact_k(5, [1, 2, 5], 5) == 1


def test_02_edge_cases():
    assert count_ways_exact_k(0, [1, 2], 0) == 1
    assert count_ways_exact_k(5, [1, 2, 5], 0) == 0
    assert count_ways_exact_k(5, [1, 2, 5], 2) == 0


def test_03_extra():
    try:
        count_ways_exact_k(-1, [1], 1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert count_ways_exact_k(6, [1, 2, 5], 2) == 1


def test_04_version_and_stdlib_only():
    assert cc_16.CC_16_VERSION == "cc-16.v1"
    assert cc_16.stdlib_only() is True
