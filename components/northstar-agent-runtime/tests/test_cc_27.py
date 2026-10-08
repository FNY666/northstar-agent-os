"""Tests for cc_27 (Batch minimum coins)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_27
from cc_27 import batch_min_coins


def test_01_normal_case():
    assert batch_min_coins([0, 1, 11, 3], [1, 2, 5]) == [0, 1, 3, 2]
    assert batch_min_coins([6, 7, 8], [1, 3, 4]) == [2, 2, 2]


def test_02_edge_cases():
    assert batch_min_coins([], [1, 2]) == []
    assert batch_min_coins([0], [5]) == [0]
    assert batch_min_coins([3], [2]) == [-1]


def test_03_extra():
    try:
        batch_min_coins([-1], [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert batch_min_coins([100], [1, 5, 10, 25]) == [4]


def test_04_version_and_stdlib_only():
    assert cc_27.CC_27_VERSION == "cc-27.v1"
    assert cc_27.stdlib_only() is True
