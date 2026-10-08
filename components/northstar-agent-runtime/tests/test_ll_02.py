"""Tests for ll_02 (merge two sorted lists)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_02
from ll_02 import merge_two, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(merge_two(from_list([1, 3, 5]), from_list([2, 4, 6]))) == [1, 2, 3, 4, 5, 6]
    assert to_list(merge_two(from_list([1, 2, 4]), from_list([1, 3, 4]))) == [1, 1, 2, 3, 4, 4]
    assert to_list(merge_two(from_list([]), from_list([]))) == []


def test_02_edge_cases():
    assert to_list(merge_two(from_list([1]), from_list([]))) == [1]
    assert to_list(merge_two(from_list([]), from_list([2]))) == [2]
    assert merge_two(None, None) is None
    assert to_list(merge_two(from_list([-3, 0]), from_list([-2, 1]))) == [-3, -2, 0, 1]


def test_03_extra():
    assert to_list(merge_two(from_list([5]), from_list([1, 2, 3, 4]))) == [1, 2, 3, 4, 5]
    assert to_list(merge_two(from_list([1, 1, 1]), from_list([1, 1]))) == [1, 1, 1, 1, 1]
    try:
        merge_two(from_list([1]), "bad")
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_02.LL_02_VERSION == "ll-02.v1"
    assert ll_02.SCHEMA_PIN == "northstar.ll-02.v1"
    assert ll_02.stdlib_only() is True
