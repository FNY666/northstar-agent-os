"""Tests for ll_13 (rotate list right by k)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_13
from ll_13 import rotate_right, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(rotate_right(from_list([1, 2, 3, 4, 5]), 2)) == [4, 5, 1, 2, 3]
    assert to_list(rotate_right(from_list([0, 1, 2]), 4)) == [2, 0, 1]
    assert to_list(rotate_right(from_list([1, 2, 3, 4, 5]), 7)) == [4, 5, 1, 2, 3]


def test_02_edge_cases():
    assert rotate_right(None, 3) is None
    assert to_list(rotate_right(from_list([7]), 5)) == [7]
    assert to_list(rotate_right(from_list([1, 2, 3]), 0)) == [1, 2, 3]
    assert to_list(rotate_right(from_list([1, 2, 3]), 3)) == [1, 2, 3]


def test_03_extra():
    assert to_list(rotate_right(from_list([1, 2]), 1)) == [2, 1]
    assert to_list(rotate_right(from_list([1, 2, 3, 4]), 6)) == [3, 4, 1, 2]
    for bad in (-1, True, 1.5, "2"):
        try:
            rotate_right(from_list([1, 2, 3]), bad)
            raised = False
        except LlError:
            raised = True
        assert raised is True, f"k={bad!r} should raise"


def test_04_version_and_stdlib_only():
    assert ll_13.LL_13_VERSION == "ll-13.v1"
    assert ll_13.SCHEMA_PIN == "northstar.ll-13.v1"
    assert ll_13.stdlib_only() is True
