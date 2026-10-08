"""Tests for greedy_05 (Maximum meetings in one room)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_05
from greedy_05 import max_meetings


def test_01_normal_case():
    assert max_meetings([1, 3, 0, 5, 8, 5], [2, 4, 6, 7, 9, 9]) == (4, [1, 2, 4, 5])


def test_02_edge_cases():
    assert max_meetings([], []) == (0, [])
    assert max_meetings([1], [2]) == (1, [1])


def test_03_extra():
    assert max_meetings([1, 2], [2, 3]) == (1, [1])
    n, chosen = max_meetings([5, 1, 3], [9, 2, 4])
    assert n == 2 and chosen == [2, 3]


def test_04_version_and_stdlib_only():
    assert greedy_05.GREEDY_05_VERSION == "greedy-05.v1"
    assert greedy_05.stdlib_only() is True
