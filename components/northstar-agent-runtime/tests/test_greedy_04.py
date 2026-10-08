"""Tests for greedy_04 (Minimum coins (canonical systems))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_04
from greedy_04 import min_coins


def test_01_normal_case():
    assert min_coins(63) == {25: 2, 10: 1, 1: 3}
    assert min_coins(41) == {25: 1, 10: 1, 5: 1, 1: 1}


def test_02_edge_cases():
    assert min_coins(0) == {}
    assert min_coins(1) == {1: 1}


def test_03_extra():
    try:
        min_coins(-5)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    try:
        min_coins(3, (2,))
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert greedy_04.GREEDY_04_VERSION == "greedy-04.v1"
    assert greedy_04.stdlib_only() is True
