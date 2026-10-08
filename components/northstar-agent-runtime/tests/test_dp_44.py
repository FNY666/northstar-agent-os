"""Tests for dp_44 (Perfect squares (minimum count))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_44
from dp_44 import num_squares


def test_01_normal_case():
    assert num_squares(12) == 3
    assert num_squares(13) == 2


def test_02_edge_cases():
    assert num_squares(0) == 0
    assert num_squares(1) == 1


def test_03_extra():
    assert num_squares(100) == 1
    assert num_squares(28) == 4
    try:
        num_squares(-9)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert dp_44.DP_44_VERSION == "dp-44.v1"
    assert dp_44.stdlib_only() is True
