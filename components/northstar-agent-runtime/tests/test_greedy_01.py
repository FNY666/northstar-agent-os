"""Tests for greedy_01 (Activity selection)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_01
from greedy_01 import max_activities


def test_01_normal_case():
    assert max_activities([(1, 2), (3, 4), (0, 6), (5, 7), (8, 9), (5, 9)]) == 4


def test_02_edge_cases():
    assert max_activities([]) == 0
    assert max_activities([(5, 5)]) == 1


def test_03_extra():
    assert max_activities([(1, 10), (2, 3), (4, 5), (6, 7)]) == 3
    assert max_activities([(1, 2), (2, 3), (3, 4)]) == 3


def test_04_version_and_stdlib_only():
    assert greedy_01.GREEDY_01_VERSION == "greedy-01.v1"
    assert greedy_01.stdlib_only() is True
