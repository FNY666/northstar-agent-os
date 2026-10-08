"""Tests for cc_06 (Greedy change + canonical-system check)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_06
from cc_06 import greedy_min_coins, is_canonical


def test_01_normal_case():
    assert greedy_min_coins(63, [25, 10, 5, 1]) == (6, [25, 25, 10, 1, 1, 1])
    assert greedy_min_coins(11, [1, 2, 5]) == (3, [5, 5, 1])


def test_02_edge_cases():
    assert greedy_min_coins(0, [1, 2]) == (0, [])
    assert greedy_min_coins(3, [2, 4]) == (-1, [])


def test_03_extra():
    assert is_canonical([25, 10, 5, 1]) is True
    assert is_canonical([1, 3, 4]) is False
    try:
        greedy_min_coins(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert cc_06.CC_06_VERSION == "cc-06.v1"
    assert cc_06.stdlib_only() is True
