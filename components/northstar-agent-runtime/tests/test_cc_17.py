"""Tests for cc_17 (Minimum coins (no repeated denomination))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_17
from cc_17 import min_coins_no_repeat


def test_01_normal_case():
    assert min_coins_no_repeat(6, [1, 5]) == 2
    assert min_coins_no_repeat(8, [1, 2, 5, 10]) == 3


def test_02_edge_cases():
    assert min_coins_no_repeat(0, [1]) == 0
    assert min_coins_no_repeat(2, [1, 1, 5]) == -1


def test_03_extra():
    try:
        min_coins_no_repeat(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # duplicates merged: needs two 1s but only one allowed
    assert min_coins_no_repeat(2, [1, 5]) == -1


def test_04_version_and_stdlib_only():
    assert cc_17.CC_17_VERSION == "cc-17.v1"
    assert cc_17.stdlib_only() is True
