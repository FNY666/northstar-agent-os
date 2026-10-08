"""Tests for ll_22 (delete duplicates II: remove all duplicated values)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_22
from ll_22 import delete_duplicates_ii, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(delete_duplicates_ii(from_list([1, 2, 3, 3, 4, 4, 5]))) == [1, 2, 5]
    assert to_list(delete_duplicates_ii(from_list([1, 1, 1, 2, 3]))) == [2, 3]
    assert to_list(delete_duplicates_ii(from_list([1, 2, 3, 3]))) == [1, 2]


def test_02_edge_cases():
    assert delete_duplicates_ii(None) is None
    assert to_list(delete_duplicates_ii(from_list([1]))) == [1]
    assert delete_duplicates_ii(from_list([1, 1, 1])) is None
    assert to_list(delete_duplicates_ii(from_list([1, 2, 3]))) == [1, 2, 3]


def test_03_extra():
    assert delete_duplicates_ii(from_list([1, 1])) is None
    assert to_list(delete_duplicates_ii(from_list([1, 2, 2, 3, 4, 4]))) == [1, 3]
    try:
        delete_duplicates_ii([1, 1])
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_22.LL_22_VERSION == "ll-22.v1"
    assert ll_22.SCHEMA_PIN == "northstar.ll-22.v1"
    assert ll_22.stdlib_only() is True
