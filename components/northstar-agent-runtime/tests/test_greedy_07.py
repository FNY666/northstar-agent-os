"""Tests for greedy_07 (Jump game reachability)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_07
from greedy_07 import can_jump


def test_01_normal_case():
    assert can_jump([2, 3, 1, 1, 4]) is True
    assert can_jump([3, 2, 1, 0, 4]) is False


def test_02_edge_cases():
    assert can_jump([0]) is True
    assert can_jump([]) is True


def test_03_extra():
    assert can_jump([1, 0]) is True
    assert can_jump([0, 1]) is False


def test_04_version_and_stdlib_only():
    assert greedy_07.GREEDY_07_VERSION == "greedy-07.v1"
    assert greedy_07.stdlib_only() is True
