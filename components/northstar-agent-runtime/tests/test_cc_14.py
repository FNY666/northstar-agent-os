"""Tests for cc_14 (Maximum coins (unbounded supply))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_14
from cc_14 import max_coins


def test_01_normal_case():
    assert max_coins(11, [1, 2, 5]) == 11
    assert max_coins(10, [2, 5]) == 5


def test_02_edge_cases():
    assert max_coins(0, [5]) == 0
    assert max_coins(3, [2]) == -1


def test_03_extra():
    try:
        max_coins(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert max_coins(7, [3, 5]) == -1
    assert max_coins(9, [3, 5]) == 3


def test_04_version_and_stdlib_only():
    assert cc_14.CC_14_VERSION == "cc-14.v1"
    assert cc_14.stdlib_only() is True
