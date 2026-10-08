"""Tests for cc_05 (Count ways (bounded supply))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_05
from cc_05 import count_ways_bounded


def test_01_normal_case():
    assert count_ways_bounded(5, [(1, 5), (2, 2), (5, 1)]) == 4
    assert count_ways_bounded(6, [(1, 6), (5, 1)]) == 2


def test_02_edge_cases():
    assert count_ways_bounded(0, [(1, 0)]) == 1
    assert count_ways_bounded(4, [(2, 1)]) == 0


def test_03_extra():
    try:
        count_ways_bounded(-3, [(1, 1)])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # caps large enough to match the unbounded answer
    assert count_ways_bounded(5, [(1, 5), (2, 5), (5, 5)]) == 4


def test_04_version_and_stdlib_only():
    assert cc_05.CC_05_VERSION == "cc-05.v1"
    assert cc_05.stdlib_only() is True
