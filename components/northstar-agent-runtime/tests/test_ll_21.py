"""Tests for ll_21 (remove all elements equal to value)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_21
from ll_21 import remove_elements, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(remove_elements(from_list([1, 2, 6, 3, 4, 5, 6]), 6)) == [1, 2, 3, 4, 5]
    assert to_list(remove_elements(from_list([1, 6, 6, 2, 6]), 6)) == [1, 2]
    assert to_list(remove_elements(from_list([7, 7, 7, 7]), 7)) == []


def test_02_edge_cases():
    assert remove_elements(None, 1) is None
    assert to_list(remove_elements(from_list([1, 2, 3]), 9)) == [1, 2, 3]
    assert remove_elements(from_list([6, 6, 6]), 6) is None
    assert to_list(remove_elements(from_list([6, 1, 2]), 6)) == [1, 2]


def test_03_extra():
    assert to_list(remove_elements(from_list([1, 2, 6]), 6)) == [1, 2]
    assert to_list(remove_elements(from_list(["a", "b", "a"]), "a")) == ["b"]
    try:
        remove_elements(object(), 1)
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_21.LL_21_VERSION == "ll-21.v1"
    assert ll_21.SCHEMA_PIN == "northstar.ll-21.v1"
    assert ll_21.stdlib_only() is True
