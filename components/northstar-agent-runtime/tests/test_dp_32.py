"""Tests for dp_32 (Triangle minimum path)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_32
from dp_32 import triangle_min


def test_01_normal_case():
    assert triangle_min([[2], [3, 4], [6, 5, 7], [4, 1, 8, 3]]) == 11
    assert triangle_min([[-1], [2, 3], [1, -1, -3]]) == -1


def test_02_edge_cases():
    assert triangle_min([[-10]]) == -10
    try:
        triangle_min([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_03_extra():
    assert triangle_min([[5], [1, 6], [4, 2, 9], [3, 7, 1, 8]]) == 9
    assert triangle_min([[0], [0, 0]]) == 0


def test_04_version_and_stdlib_only():
    assert dp_32.DP_32_VERSION == "dp-32.v1"
    assert dp_32.stdlib_only() is True
