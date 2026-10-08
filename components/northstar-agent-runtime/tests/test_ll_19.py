"""Tests for ll_19 (reorder list: L0 -> Ln -> L1 -> Ln-1 ...)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_19
from ll_19 import reorder_list, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(reorder_list(from_list([1, 2, 3, 4]))) == [1, 4, 2, 3]
    assert to_list(reorder_list(from_list([1, 2, 3, 4, 5]))) == [1, 5, 2, 4, 3]
    assert to_list(reorder_list(from_list([1, 2, 3, 4, 5, 6]))) == [1, 6, 2, 5, 3, 4]


def test_02_edge_cases():
    assert reorder_list(None) is None
    assert to_list(reorder_list(from_list([1]))) == [1]
    assert to_list(reorder_list(from_list([1, 2]))) == [1, 2]
    assert to_list(reorder_list(from_list([1, 2, 3]))) == [1, 3, 2]


def test_03_extra():
    head = from_list([1, 2, 3, 4])
    out = reorder_list(head)
    assert out is head
    assert to_list(out) == [1, 4, 2, 3]
    try:
        reorder_list([1, 2])
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_19.LL_19_VERSION == "ll-19.v1"
    assert ll_19.SCHEMA_PIN == "northstar.ll-19.v1"
    assert ll_19.stdlib_only() is True
