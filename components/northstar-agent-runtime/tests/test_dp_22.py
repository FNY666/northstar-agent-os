"""Tests for dp_22 (Partition equal subset sum)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_22
from dp_22 import can_partition


def test_01_normal_case():
    assert can_partition([1, 5, 11, 5]) is True
    assert can_partition([1, 2, 3, 5]) is False


def test_02_edge_cases():
    assert can_partition([]) is True
    assert can_partition([7]) is False


def test_03_extra():
    assert can_partition([1, 2, 5]) is False
    assert can_partition([14, 9, 8, 4, 3, 2]) is True


def test_04_version_and_stdlib_only():
    assert dp_22.DP_22_VERSION == "dp-22.v1"
    assert dp_22.stdlib_only() is True
