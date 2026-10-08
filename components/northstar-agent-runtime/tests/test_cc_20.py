"""Tests for cc_20 (Count ways modulo m)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_20
from cc_20 import count_ways_mod


def test_01_normal_case():
    assert count_ways_mod(5, [1, 2, 5]) == 4
    assert count_ways_mod(10, [1, 5], 100) == 3


def test_02_edge_cases():
    assert count_ways_mod(0, [1, 2], 7) == 1
    assert count_ways_mod(3, [2], 100) == 0


def test_03_extra():
    try:
        count_ways_mod(5, [1], 0)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # default modulus matches the raw count here
    assert count_ways_mod(100, [1, 5, 10, 25]) == 292


def test_04_version_and_stdlib_only():
    assert cc_20.CC_20_VERSION == "cc-20.v1"
    assert cc_20.stdlib_only() is True
