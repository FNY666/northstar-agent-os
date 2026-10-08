"""Tests for cc_33 (Subset-sum feasibility)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_33
from cc_33 import subset_sum


def test_01_normal_case():
    assert subset_sum([1, 2, 5, 10], 8) is True
    assert subset_sum([3, 34, 4, 12, 5, 2], 9) is True


def test_02_edge_cases():
    assert subset_sum([3], 0) is True
    assert subset_sum([1, 2, 5, 10], 9) is False
    assert subset_sum([], 5) is False


def test_03_extra():
    try:
        subset_sum([1], -1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert subset_sum([2, 4, 6], 11) is False
    assert subset_sum([2, 4, 6], 12) is True


def test_04_version_and_stdlib_only():
    assert cc_33.CC_33_VERSION == "cc-33.v1"
    assert cc_33.stdlib_only() is True
