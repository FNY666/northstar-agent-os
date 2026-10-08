"""Tests for ll_12 (add two numbers, digits in reverse order)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_12
from ll_12 import add_two_numbers, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(add_two_numbers(from_list([2, 4, 3]), from_list([5, 6, 4]))) == [7, 0, 8]
    assert to_list(add_two_numbers(from_list([9, 9]), from_list([1]))) == [0, 0, 1]
    assert to_list(add_two_numbers(from_list([9, 9, 9]), from_list([1]))) == [0, 0, 0, 1]


def test_02_edge_cases():
    assert to_list(add_two_numbers(from_list([0]), from_list([0]))) == [0]
    assert to_list(add_two_numbers(from_list([]), from_list([]))) == [0]
    assert to_list(add_two_numbers(from_list([5]), from_list([5]))) == [0, 1]
    assert to_list(add_two_numbers(from_list([1, 8]), from_list([0]))) == [1, 8]


def test_03_extra():
    assert to_list(add_two_numbers(from_list([9, 9, 9, 9]), from_list([9, 9, 9, 9]))) == [8, 9, 9, 9, 1]
    for bad in (from_list([1, 10]), from_list(["a"])):
        try:
            add_two_numbers(bad, from_list([2]))
            raised = False
        except LlError:
            raised = True
        assert raised is True, f"{bad!r} should raise"


def test_04_version_and_stdlib_only():
    assert ll_12.LL_12_VERSION == "ll-12.v1"
    assert ll_12.SCHEMA_PIN == "northstar.ll-12.v1"
    assert ll_12.stdlib_only() is True
