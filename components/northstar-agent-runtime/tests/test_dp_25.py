"""Tests for dp_25 (Maximum product subarray)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_25
from dp_25 import max_product


def test_01_normal_case():
    assert max_product([2, 3, -2, 4]) == 6
    assert max_product([-2, 3, -4]) == 24


def test_02_edge_cases():
    assert max_product([-2]) == -2
    assert max_product([0, 2]) == 2


def test_03_extra():
    assert max_product([2, -5, -2, -4, 3]) == 24
    try:
        max_product([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert dp_25.DP_25_VERSION == "dp-25.v1"
    assert dp_25.stdlib_only() is True
