"""Tests for greedy_22 (Boats to save people)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_22
from greedy_22 import num_boats


def test_01_normal_case():
    assert num_boats([1, 2], 3) == 1
    assert num_boats([3, 2, 2, 1], 3) == 3


def test_02_edge_cases():
    assert num_boats([], 5) == 0
    assert num_boats([5], 5) == 1


def test_03_extra():
    assert num_boats([3, 5, 3, 4], 5) == 4
    assert num_boats([2, 2, 2, 2], 4) == 2


def test_04_version_and_stdlib_only():
    assert greedy_22.GREEDY_22_VERSION == "greedy-22.v1"
    assert greedy_22.stdlib_only() is True
