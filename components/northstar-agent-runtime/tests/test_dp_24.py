"""Tests for dp_24 (Maximum subarray (Kadane))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_24
from dp_24 import max_subarray


def test_01_normal_case():
    assert max_subarray([-2, 1, -3, 4, -1, 2, 1, -5, 4]) == 6
    assert max_subarray([5, 4, -1, 7, 8]) == 23


def test_02_edge_cases():
    assert max_subarray([-1]) == -1
    assert max_subarray([1]) == 1


def test_03_extra():
    assert max_subarray([1, 2, 3, 4, 5]) == 15
    try:
        max_subarray([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert dp_24.DP_24_VERSION == "dp-24.v1"
    assert dp_24.stdlib_only() is True
