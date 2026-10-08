"""Tests for cc_01 (Minimum coins (unbounded supply))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_01
from cc_01 import min_coins


def test_01_normal_case():
    assert min_coins(11, [1, 2, 5]) == 3
    assert min_coins(6, [1, 3, 4]) == 2
    assert min_coins(27, [1, 2, 5, 10]) == 4


def test_02_edge_cases():
    assert min_coins(0, [1, 2, 5]) == 0
    assert min_coins(3, [2]) == -1
    assert min_coins(1, [2, 5]) == -1


def test_03_extra():
    try:
        min_coins(-5, [1, 2])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    try:
        min_coins(5, [1, 0])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins(100, [1, 5, 10, 25]) == 4


def test_04_version_and_stdlib_only():
    assert cc_01.CC_01_VERSION == "cc-01.v1"
    assert cc_01.stdlib_only() is True
