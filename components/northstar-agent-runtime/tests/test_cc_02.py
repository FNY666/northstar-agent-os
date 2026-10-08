"""Tests for cc_02 (Count ways (combinations, order ignored))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_02
from cc_02 import count_ways


def test_01_normal_case():
    assert count_ways(5, [1, 2, 5]) == 4
    assert count_ways(10, [2, 5, 3, 6]) == 5


def test_02_edge_cases():
    assert count_ways(0, [1, 2]) == 1
    assert count_ways(3, [2]) == 0
    assert count_ways(1, [2, 3]) == 0


def test_03_extra():
    try:
        count_ways(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert count_ways(100, [1, 5, 10, 25]) == 292


def test_04_version_and_stdlib_only():
    assert cc_02.CC_02_VERSION == "cc-02.v1"
    assert cc_02.stdlib_only() is True
