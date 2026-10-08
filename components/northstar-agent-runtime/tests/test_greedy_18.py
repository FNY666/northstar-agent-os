"""Tests for greedy_18 (Wiggle subsequence)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_18
from greedy_18 import wiggle_max_length


def test_01_normal_case():
    assert wiggle_max_length([1, 7, 4, 9, 2, 5]) == 6
    assert wiggle_max_length([1, 17, 5, 10, 13, 15, 10, 5, 16, 8]) == 7


def test_02_edge_cases():
    assert wiggle_max_length([]) == 0
    assert wiggle_max_length([3]) == 1


def test_03_extra():
    assert wiggle_max_length([1, 2, 3, 4, 5, 6, 7, 8, 9]) == 2
    assert wiggle_max_length([1, 1, 1]) == 1


def test_04_version_and_stdlib_only():
    assert greedy_18.GREEDY_18_VERSION == "greedy-18.v1"
    assert greedy_18.stdlib_only() is True
