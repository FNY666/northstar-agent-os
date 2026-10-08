"""Tests for dp_23 (Target sum (ways to assign signs))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_23
from dp_23 import target_sum_ways


def test_01_normal_case():
    assert target_sum_ways([1, 1, 1, 1, 1], 3) == 5
    assert target_sum_ways([1], 1) == 1


def test_02_edge_cases():
    assert target_sum_ways([], 0) == 1
    assert target_sum_ways([1, 2], 4) == 0


def test_03_extra():
    assert target_sum_ways([0, 0, 0, 0, 1], 1) == 16
    assert target_sum_ways([2, 2, 2], 2) == 3


def test_04_version_and_stdlib_only():
    assert dp_23.DP_23_VERSION == "dp-23.v1"
    assert dp_23.stdlib_only() is True
