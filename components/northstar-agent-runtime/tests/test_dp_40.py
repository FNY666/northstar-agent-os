"""Tests for dp_40 (Burst balloons)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_40
from dp_40 import burst_balloons


def test_01_normal_case():
    assert burst_balloons([3, 1, 5, 8]) == 167
    assert burst_balloons([1, 5]) == 10


def test_02_edge_cases():
    assert burst_balloons([]) == 0
    assert burst_balloons([7]) == 7


def test_03_extra():
    assert burst_balloons([2, 2]) == 6
    assert burst_balloons([9, 76, 64, 21]) == 116718


def test_04_version_and_stdlib_only():
    assert dp_40.DP_40_VERSION == "dp-40.v1"
    assert dp_40.stdlib_only() is True
