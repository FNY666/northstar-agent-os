"""Tests for cc_10 (Count ways (0/1, each coin used at most once))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_10
from cc_10 import count_ways_01


def test_01_normal_case():
    assert count_ways_01(8, [1, 2, 5, 10]) == 1
    assert count_ways_01(3, [1, 2, 3]) == 2


def test_02_edge_cases():
    assert count_ways_01(0, [1]) == 1
    assert count_ways_01(9, [1, 2, 5, 10]) == 0


def test_03_extra():
    try:
        count_ways_01(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert count_ways_01(6, [1, 2, 3, 4]) == 2


def test_04_version_and_stdlib_only():
    assert cc_10.CC_10_VERSION == "cc-10.v1"
    assert cc_10.stdlib_only() is True
