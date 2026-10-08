"""Tests for greedy_30 (Furthest building you can reach)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_30
from greedy_30 import furthest_building


def test_01_normal_case():
    assert furthest_building([4, 2, 7, 6, 9, 14, 12], 5, 1) == 4
    assert furthest_building([4, 12, 2, 7, 3, 18, 20, 3, 19], 10, 2) == 7


def test_02_edge_cases():
    assert furthest_building([1, 2], 0, 0) == 0
    assert furthest_building([5], 0, 0) == 0


def test_03_extra():
    assert furthest_building([1, 2, 3], 10, 0) == 2
    assert furthest_building([1, 5, 1, 2, 3, 4, 10000], 4, 1) == 5


def test_04_version_and_stdlib_only():
    assert greedy_30.GREEDY_30_VERSION == "greedy-30.v1"
    assert greedy_30.stdlib_only() is True
