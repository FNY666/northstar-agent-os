"""Tests for ll_14 (swap nodes in pairs)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_14
from ll_14 import swap_pairs, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(swap_pairs(from_list([1, 2, 3, 4]))) == [2, 1, 4, 3]
    assert to_list(swap_pairs(from_list([1, 2, 3]))) == [2, 1, 3]
    assert to_list(swap_pairs(from_list([1, 2, 3, 4, 5]))) == [2, 1, 4, 3, 5]


def test_02_edge_cases():
    assert swap_pairs(None) is None
    assert to_list(swap_pairs(from_list([1]))) == [1]
    assert to_list(swap_pairs(from_list([1, 2]))) == [2, 1]


def test_03_extra():
    assert to_list(swap_pairs(from_list([1, 2, 3, 4, 5, 6]))) == [2, 1, 4, 3, 6, 5]
    try:
        swap_pairs([1, 2])
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_14.LL_14_VERSION == "ll-14.v1"
    assert ll_14.SCHEMA_PIN == "northstar.ll-14.v1"
    assert ll_14.stdlib_only() is True
