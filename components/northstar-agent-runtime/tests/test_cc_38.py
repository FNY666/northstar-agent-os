"""Tests for cc_38 (Count ways with per-denomination caps)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_38
from cc_38 import count_ways_caps


def test_01_normal_case():
    assert count_ways_caps(5, {1: 5, 2: 5, 5: 5}) == 4
    assert count_ways_caps(6, {1: 6, 5: 1}) == 2


def test_02_edge_cases():
    assert count_ways_caps(0, {1: 0}) == 1
    assert count_ways_caps(5, {5: 0}) == 0


def test_03_extra():
    try:
        count_ways_caps(-1, {1: 1})
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # cap of 1 on 5s removes the {5,5} and {5,...} ways appropriately
    assert count_ways_caps(10, {1: 10, 5: 1}) == 2


def test_04_version_and_stdlib_only():
    assert cc_38.CC_38_VERSION == "cc-38.v1"
    assert cc_38.stdlib_only() is True
