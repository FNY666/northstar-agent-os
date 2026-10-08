"""Tests for dp_10 (Longest increasing subsequence (length))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_10
from dp_10 import lis


def test_01_normal_case():
    assert lis([10, 9, 2, 5, 3, 7, 101, 18]) == 4
    assert lis([0, 1, 0, 3, 2, 3]) == 4


def test_02_edge_cases():
    assert lis([]) == 0
    assert lis([7, 7, 7]) == 1


def test_03_extra():
    assert lis([1, 3, 6, 7, 9, 4, 10, 5, 6]) == 6
    assert lis([-1, -2, -3]) == 1


def test_04_version_and_stdlib_only():
    assert dp_10.DP_10_VERSION == "dp-10.v1"
    assert dp_10.stdlib_only() is True
