"""Tests for greedy_25 (Queue reconstruction by height)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_25
from greedy_25 import reconstruct_queue


def test_01_normal_case():
    assert reconstruct_queue([[7, 0], [4, 4], [7, 1], [5, 0], [6, 1], [5, 2]]) == [[5, 0], [7, 0], [5, 2], [6, 1], [4, 4], [7, 1]]


def test_02_edge_cases():
    assert reconstruct_queue([]) == []
    assert reconstruct_queue([[6, 0]]) == [[6, 0]]


def test_03_extra():
    assert reconstruct_queue([[6, 0], [5, 0], [4, 0], [3, 2], [2, 2], [1, 4]]) == [[4, 0], [5, 0], [2, 2], [3, 2], [1, 4], [6, 0]]


def test_04_version_and_stdlib_only():
    assert greedy_25.GREEDY_25_VERSION == "greedy-25.v1"
    assert greedy_25.stdlib_only() is True
