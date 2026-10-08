"""Tests for dp_31 (Minimum path sum in a grid)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_31
from dp_31 import min_path_sum


def test_01_normal_case():
    assert min_path_sum([[1, 3, 1], [1, 5, 1], [4, 2, 1]]) == 7
    assert min_path_sum([[1, 2, 3], [4, 5, 6]]) == 12


def test_02_edge_cases():
    assert min_path_sum([[5]]) == 5
    try:
        min_path_sum([[]])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_03_extra():
    assert min_path_sum([[1, 4, 8, 6], [2, 1, 7, 3]]) == 14
    assert min_path_sum([[0, 0], [0, 0]]) == 0


def test_04_version_and_stdlib_only():
    assert dp_31.DP_31_VERSION == "dp-31.v1"
    assert dp_31.stdlib_only() is True
