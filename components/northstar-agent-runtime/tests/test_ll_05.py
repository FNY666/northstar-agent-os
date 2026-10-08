"""Tests for ll_05 (remove nth node from end)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_05
from ll_05 import remove_nth_from_end, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(remove_nth_from_end(from_list([1, 2, 3, 4, 5]), 2)) == [1, 2, 3, 5]
    assert to_list(remove_nth_from_end(from_list([1, 2, 3, 4, 5]), 5)) == [2, 3, 4, 5]
    assert to_list(remove_nth_from_end(from_list([1, 2, 3]), 1)) == [1, 2]


def test_02_edge_cases():
    assert remove_nth_from_end(from_list([9]), 1) is None
    assert to_list(remove_nth_from_end(from_list([1, 2]), 2)) == [2]
    assert to_list(remove_nth_from_end(from_list([1, 2]), 1)) == [1]


def test_03_extra():
    assert to_list(remove_nth_from_end(from_list([1, 2, 3, 4]), 3)) == [1, 3, 4]
    for bad_n in (0, -1, 10, True, "2"):
        try:
            remove_nth_from_end(from_list([1, 2, 3]), bad_n)
            raised = False
        except LlError:
            raised = True
        assert raised is True, f"n={bad_n!r} should raise"


def test_04_version_and_stdlib_only():
    assert ll_05.LL_05_VERSION == "ll-05.v1"
    assert ll_05.SCHEMA_PIN == "northstar.ll-05.v1"
    assert ll_05.stdlib_only() is True
