"""Tests for ll_10 (remove duplicates from unsorted list)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_10
from ll_10 import delete_duplicates_unsorted, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(delete_duplicates_unsorted(from_list([1, 2, 1, 3, 2]))) == [1, 2, 3]
    assert to_list(delete_duplicates_unsorted(from_list([3, 1, 2, 3, 1]))) == [3, 1, 2]
    assert to_list(delete_duplicates_unsorted(from_list([1, 1, 2, 2, 3, 3]))) == [1, 2, 3]


def test_02_edge_cases():
    assert delete_duplicates_unsorted(None) is None
    assert to_list(delete_duplicates_unsorted(from_list([1]))) == [1]
    assert to_list(delete_duplicates_unsorted(from_list([1, 1, 1]))) == [1]
    assert to_list(delete_duplicates_unsorted(from_list([1, 2, 3]))) == [1, 2, 3]


def test_03_extra():
    assert to_list(delete_duplicates_unsorted(from_list(["a", "b", "a", "c"]))) == ["a", "b", "c"]
    for bad in (42, from_list([[1], [1]])):
        try:
            delete_duplicates_unsorted(bad)
            raised = False
        except LlError:
            raised = True
        assert raised is True, f"{bad!r} should raise"


def test_04_version_and_stdlib_only():
    assert ll_10.LL_10_VERSION == "ll-10.v1"
    assert ll_10.SCHEMA_PIN == "northstar.ll-10.v1"
    assert ll_10.stdlib_only() is True
