"""Tests for dp_15 (Rod cutting)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_15
from dp_15 import rod_cut


def test_01_normal_case():
    assert rod_cut([1, 5, 8, 9, 10, 17, 17, 20], 8) == 22
    assert rod_cut([3, 5, 8, 9, 10, 17, 17, 20], 8) == 24


def test_02_edge_cases():
    assert rod_cut([1, 5, 8, 9, 10, 17, 17, 20], 0) == 0
    assert rod_cut([2], 1) == 2


def test_03_extra():
    assert rod_cut([1, 5, 8, 9, 10, 17, 17, 20], 4) == 10
    try:
        rod_cut([1], -4)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert dp_15.DP_15_VERSION == "dp-15.v1"
    assert dp_15.stdlib_only() is True
