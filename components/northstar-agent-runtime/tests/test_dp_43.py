"""Tests for dp_43 (Partition to K equal-sum subsets)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_43
from dp_43 import can_partition_k


def test_01_normal_case():
    assert can_partition_k([4, 3, 2, 3, 5, 2, 1], 4) is True
    assert can_partition_k([2, 2, 2, 2, 3, 3, 3, 3], 4) is True


def test_02_edge_cases():
    assert can_partition_k([], 2) is False
    assert can_partition_k([1, 2, 3], 0) is False
    assert can_partition_k([5], 2) is False


def test_03_extra():
    assert can_partition_k([1, 1, 1, 1], 4) is True
    assert can_partition_k([10, 10, 10, 7, 7, 7, 7, 7, 7], 3) is True


def test_04_version_and_stdlib_only():
    assert dp_43.DP_43_VERSION == "dp-43.v1"
    assert dp_43.stdlib_only() is True
