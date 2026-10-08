"""Tests for greedy_12 (Merge intervals)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_12
from greedy_12 import merge_intervals


def test_01_normal_case():
    assert merge_intervals([[1, 3], [2, 6], [8, 10], [15, 18]]) == [[1, 6], [8, 10], [15, 18]]


def test_02_edge_cases():
    assert merge_intervals([]) == []
    assert merge_intervals([[1, 2]]) == [[1, 2]]


def test_03_extra():
    assert merge_intervals([[1, 4], [4, 5]]) == [[1, 5]]
    assert merge_intervals([[1, 4], [0, 4]]) == [[0, 4]]


def test_04_version_and_stdlib_only():
    assert greedy_12.GREEDY_12_VERSION == "greedy-12.v1"
    assert greedy_12.stdlib_only() is True
