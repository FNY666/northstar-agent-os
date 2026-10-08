"""Tests for ll_09 (remove duplicates from sorted list)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_09
from ll_09 import delete_duplicates_sorted, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(delete_duplicates_sorted(from_list([1, 1, 2]))) == [1, 2]
    assert to_list(delete_duplicates_sorted(from_list([1, 1, 2, 3, 3]))) == [1, 2, 3]
    assert to_list(delete_duplicates_sorted(from_list([1, 1, 1, 2, 2, 3]))) == [1, 2, 3]


def test_02_edge_cases():
    assert delete_duplicates_sorted(None) is None
    assert to_list(delete_duplicates_sorted(from_list([1]))) == [1]
    assert to_list(delete_duplicates_sorted(from_list([1, 2, 3]))) == [1, 2, 3]


def test_03_extra():
    assert to_list(delete_duplicates_sorted(from_list([1, 1, 1]))) == [1]
    assert to_list(delete_duplicates_sorted(from_list([1, 2, 2, 2]))) == [1, 2]
    try:
        delete_duplicates_sorted({"a": 1})
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_09.LL_09_VERSION == "ll-09.v1"
    assert ll_09.SCHEMA_PIN == "northstar.ll-09.v1"
    assert ll_09.stdlib_only() is True
