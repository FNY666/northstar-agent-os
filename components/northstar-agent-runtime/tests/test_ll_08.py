"""Tests for ll_08 (merge k sorted lists)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_08
from ll_08 import merge_k, from_list, to_list, LlError


def test_01_normal_case():
    lists = [from_list([1, 4, 5]), from_list([1, 3, 4]), from_list([2, 6])]
    assert to_list(merge_k(lists)) == [1, 1, 2, 3, 4, 4, 5, 6]
    assert to_list(merge_k([from_list([1, 2]), from_list([3, 4])])) == [1, 2, 3, 4]


def test_02_edge_cases():
    assert merge_k([]) is None
    assert merge_k([None, None]) is None
    assert to_list(merge_k([from_list([1, 2])])) == [1, 2]
    assert to_list(merge_k([None, from_list([3])])) == [3]


def test_03_extra():
    lists = [from_list([v]) for v in (5, 1, 4, 2, 3)]
    assert to_list(merge_k(lists)) == [1, 2, 3, 4, 5]
    try:
        merge_k("bad")
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_08.LL_08_VERSION == "ll-08.v1"
    assert ll_08.SCHEMA_PIN == "northstar.ll-08.v1"
    assert ll_08.stdlib_only() is True
