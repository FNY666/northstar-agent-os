"""Tests for ll_18 (partition list around value x)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_18
from ll_18 import partition, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(partition(from_list([1, 4, 3, 2, 5, 2]), 3)) == [1, 2, 2, 4, 3, 5]
    assert to_list(partition(from_list([3, 1, 2, 1, 3]), 2)) == [1, 1, 3, 2, 3]


def test_02_edge_cases():
    assert partition(None, 3) is None
    assert to_list(partition(from_list([1, 2]), 5)) == [1, 2]
    assert to_list(partition(from_list([5, 6]), 5)) == [5, 6]
    assert to_list(partition(from_list([1]), 1)) == [1]


def test_03_extra():
    assert to_list(partition(from_list([1, 2, 3]), 0)) == [1, 2, 3]
    assert to_list(partition(from_list([1, 2, 3]), 10)) == [1, 2, 3]
    for bad_head in (42, from_list([1, "a"])):
        try:
            partition(bad_head, 2)
            raised = False
        except LlError:
            raised = True
        assert raised is True, f"{bad_head!r} should raise"


def test_04_version_and_stdlib_only():
    assert ll_18.LL_18_VERSION == "ll-18.v1"
    assert ll_18.SCHEMA_PIN == "northstar.ll-18.v1"
    assert ll_18.stdlib_only() is True
