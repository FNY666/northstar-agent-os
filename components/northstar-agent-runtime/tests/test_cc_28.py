"""Tests for cc_28 (Batch count ways)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_28
from cc_28 import batch_count_ways


def test_01_normal_case():
    assert batch_count_ways([0, 5], [1, 2, 5]) == [1, 4]
    assert batch_count_ways([4, 5], [1, 2, 3]) == [4, 5]


def test_02_edge_cases():
    assert batch_count_ways([], [1]) == []
    assert batch_count_ways([0], [2]) == [1]
    assert batch_count_ways([3], [2]) == [0]


def test_03_extra():
    try:
        batch_count_ways([-2], [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert batch_count_ways([100], [1, 5, 10, 25]) == [292]


def test_04_version_and_stdlib_only():
    assert cc_28.CC_28_VERSION == "cc-28.v1"
    assert cc_28.stdlib_only() is True
