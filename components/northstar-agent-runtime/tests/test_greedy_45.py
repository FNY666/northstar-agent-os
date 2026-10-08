"""Tests for greedy_45 (Reduce array size to the half)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_45
from greedy_45 import min_set_size


def test_01_normal_case():
    assert min_set_size([3, 3, 3, 3, 5, 5, 5, 2, 2, 7]) == 2
    assert min_set_size([7, 7, 7, 7, 7, 7]) == 1


def test_02_edge_cases():
    assert min_set_size([1, 9]) == 1
    assert min_set_size([1]) == 1


def test_03_extra():
    assert min_set_size([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) == 5
    assert min_set_size([1000, 1000, 3, 7]) == 1


def test_04_version_and_stdlib_only():
    assert greedy_45.GREEDY_45_VERSION == "greedy-45.v1"
    assert greedy_45.stdlib_only() is True
