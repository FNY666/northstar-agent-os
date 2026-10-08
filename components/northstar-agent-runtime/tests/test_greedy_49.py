"""Tests for greedy_49 (Largest perimeter triangle)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_49
from greedy_49 import largest_perimeter


def test_01_normal_case():
    assert largest_perimeter([2, 1, 2]) == 5
    assert largest_perimeter([1, 2, 1]) == 0


def test_02_edge_cases():
    assert largest_perimeter([]) == 0
    assert largest_perimeter([5]) == 0


def test_03_extra():
    assert largest_perimeter([3, 6, 2, 3]) == 8
    assert largest_perimeter([1, 2, 3, 4, 5, 6]) == 15


def test_04_version_and_stdlib_only():
    assert greedy_49.GREEDY_49_VERSION == "greedy-49.v1"
    assert greedy_49.stdlib_only() is True
