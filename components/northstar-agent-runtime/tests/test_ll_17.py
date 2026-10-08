"""Tests for ll_17 (odd-even linked list)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_17
from ll_17 import odd_even_list, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(odd_even_list(from_list([1, 2, 3, 4, 5]))) == [1, 3, 5, 2, 4]
    assert to_list(odd_even_list(from_list([1, 2, 3, 4]))) == [1, 3, 2, 4]
    assert to_list(odd_even_list(from_list([2, 1, 4, 3, 6, 5]))) == [2, 4, 6, 1, 3, 5]


def test_02_edge_cases():
    assert odd_even_list(None) is None
    assert to_list(odd_even_list(from_list([1]))) == [1]
    assert to_list(odd_even_list(from_list([1, 2]))) == [1, 2]
    assert to_list(odd_even_list(from_list([1, 2, 3]))) == [1, 3, 2]


def test_03_extra():
    assert to_list(odd_even_list(from_list([1, 2, 3, 4, 5, 6, 7]))) == [1, 3, 5, 7, 2, 4, 6]
    try:
        odd_even_list("bad")
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_17.LL_17_VERSION == "ll-17.v1"
    assert ll_17.SCHEMA_PIN == "northstar.ll-17.v1"
    assert ll_17.stdlib_only() is True
