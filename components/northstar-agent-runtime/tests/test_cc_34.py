"""Tests for cc_34 (Subset-sum counting)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_34
from cc_34 import subset_sum_count


def test_01_normal_case():
    assert subset_sum_count([1, 2, 3], 3) == 2
    assert subset_sum_count([1, 2, 3, 4], 6) == 2


def test_02_edge_cases():
    assert subset_sum_count([5], 0) == 1
    assert subset_sum_count([1, 2, 5], 8) == 0
    assert subset_sum_count([], 3) == 0


def test_03_extra():
    try:
        subset_sum_count([1], -1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert subset_sum_count([2, 2, 2], 4) == 3


def test_04_version_and_stdlib_only():
    assert cc_34.CC_34_VERSION == "cc-34.v1"
    assert cc_34.stdlib_only() is True
