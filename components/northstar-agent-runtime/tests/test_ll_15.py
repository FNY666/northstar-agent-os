"""Tests for ll_15 (reverse nodes in k-group)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_15
from ll_15 import reverse_k_group, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(reverse_k_group(from_list([1, 2, 3, 4, 5]), 2)) == [2, 1, 4, 3, 5]
    assert to_list(reverse_k_group(from_list([1, 2, 3, 4, 5]), 3)) == [3, 2, 1, 4, 5]
    assert to_list(reverse_k_group(from_list([1, 2, 3, 4, 5, 6, 7, 8]), 4)) == [4, 3, 2, 1, 8, 7, 6, 5]


def test_02_edge_cases():
    assert reverse_k_group(None, 3) is None
    assert to_list(reverse_k_group(from_list([1, 2, 3]), 1)) == [1, 2, 3]
    assert to_list(reverse_k_group(from_list([1, 2, 3]), 3)) == [3, 2, 1]
    assert to_list(reverse_k_group(from_list([1, 2]), 5)) == [1, 2]


def test_03_extra():
    assert to_list(reverse_k_group(from_list([1, 2, 3, 4]), 2)) == [2, 1, 4, 3]
    for bad in (0, -2, True, 2.0, "2"):
        try:
            reverse_k_group(from_list([1, 2, 3]), bad)
            raised = False
        except LlError:
            raised = True
        assert raised is True, f"k={bad!r} should raise"


def test_04_version_and_stdlib_only():
    assert ll_15.LL_15_VERSION == "ll-15.v1"
    assert ll_15.SCHEMA_PIN == "northstar.ll-15.v1"
    assert ll_15.stdlib_only() is True
