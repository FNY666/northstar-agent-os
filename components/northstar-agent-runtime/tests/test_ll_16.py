"""Tests for ll_16 (sort list, merge sort on linked list)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_16
from ll_16 import sort_list, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(sort_list(from_list([4, 2, 1, 3]))) == [1, 2, 3, 4]
    assert to_list(sort_list(from_list([-1, 5, 3, 0, -4]))) == [-4, -1, 0, 3, 5]
    assert to_list(sort_list(from_list([3, 1, 2, 1, 3]))) == [1, 1, 2, 3, 3]


def test_02_edge_cases():
    assert sort_list(None) is None
    assert to_list(sort_list(from_list([1]))) == [1]
    assert to_list(sort_list(from_list([1, 2, 3]))) == [1, 2, 3]
    assert to_list(sort_list(from_list([3, 2, 1]))) == [1, 2, 3]


def test_03_extra():
    vals = [9, 7, 5, 3, 1, 2, 4, 6, 8, 0]
    assert to_list(sort_list(from_list(vals))) == sorted(vals)
    for bad in ({"v": 1}, from_list([1, "a"])):
        try:
            sort_list(bad)
            raised = False
        except LlError:
            raised = True
        assert raised is True, f"{bad!r} should raise"


def test_04_version_and_stdlib_only():
    assert ll_16.LL_16_VERSION == "ll-16.v1"
    assert ll_16.SCHEMA_PIN == "northstar.ll-16.v1"
    assert ll_16.stdlib_only() is True
