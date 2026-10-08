"""Tests for cc_24 (Count ways via memoized recursion)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_24
from cc_24 import count_ways_memo


def test_01_normal_case():
    assert count_ways_memo(5, [1, 2, 5]) == 4
    assert count_ways_memo(10, [2, 5, 3, 6]) == 5


def test_02_edge_cases():
    assert count_ways_memo(0, [1, 2]) == 1
    assert count_ways_memo(3, [2]) == 0


def test_03_extra():
    try:
        count_ways_memo(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert count_ways_memo(100, [1, 5, 10, 25]) == 292


def test_04_version_and_stdlib_only():
    assert cc_24.CC_24_VERSION == "cc-24.v1"
    assert cc_24.stdlib_only() is True
