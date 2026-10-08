"""Tests for ll_24 (insert value into sorted list)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_24
from ll_24 import insert_sorted, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(insert_sorted(from_list([1, 3, 5]), 4)) == [1, 3, 4, 5]
    assert to_list(insert_sorted(from_list([1, 2, 2, 3]), 2)) == [1, 2, 2, 2, 3]
    assert to_list(insert_sorted(from_list([-5, 0, 5]), -1)) == [-5, -1, 0, 5]


def test_02_edge_cases():
    assert to_list(insert_sorted(None, 2)) == [2]
    assert to_list(insert_sorted(from_list([2, 3]), 1)) == [1, 2, 3]
    assert to_list(insert_sorted(from_list([1, 2]), 5)) == [1, 2, 5]
    assert to_list(insert_sorted(from_list([1]), 1)) == [1, 1]


def test_03_extra():
    assert to_list(insert_sorted(from_list([1, 3]), 2)) == [1, 2, 3]
    for bad_head, bad_val in ((42, 1), (from_list([1, 2]), "a")):
        try:
            insert_sorted(bad_head, bad_val)
            raised = False
        except LlError:
            raised = True
        assert raised is True, f"({bad_head!r}, {bad_val!r}) should raise"


def test_04_version_and_stdlib_only():
    assert ll_24.LL_24_VERSION == "ll-24.v1"
    assert ll_24.SCHEMA_PIN == "northstar.ll-24.v1"
    assert ll_24.stdlib_only() is True
