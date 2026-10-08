"""Tests for greedy_11 (Non-overlapping intervals (erase overlap))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_11
from greedy_11 import erase_overlap_intervals


def test_01_normal_case():
    assert erase_overlap_intervals([[1, 2], [2, 3], [3, 4], [1, 3]]) == 1


def test_02_edge_cases():
    assert erase_overlap_intervals([]) == 0
    assert erase_overlap_intervals([[1, 2]]) == 0


def test_03_extra():
    assert erase_overlap_intervals([[1, 2], [1, 2], [1, 2]]) == 2
    assert erase_overlap_intervals([[1, 2], [2, 3]]) == 0


def test_04_version_and_stdlib_only():
    assert greedy_11.GREEDY_11_VERSION == "greedy-11.v1"
    assert greedy_11.stdlib_only() is True
