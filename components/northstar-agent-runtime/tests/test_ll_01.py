"""Tests for ll_01 (reverse linked list, iterative)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_01
from ll_01 import reverse_list, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(reverse_list(from_list([1, 2, 3]))) == [3, 2, 1]
    assert to_list(reverse_list(from_list([1, 2, 3, 4, 5]))) == [5, 4, 3, 2, 1]
    assert to_list(reverse_list(from_list([10, 20, 30, 40]))) == [40, 30, 20, 10]


def test_02_edge_cases():
    assert to_list(reverse_list(from_list([]))) == []
    assert reverse_list(None) is None
    assert to_list(reverse_list(from_list([42]))) == [42]


def test_03_extra():
    head = from_list([1, 2, 3])
    out = reverse_list(head)
    assert to_list(out) == [3, 2, 1]
    assert to_list(reverse_list(reverse_list(from_list([1, 2, 3])))) == [1, 2, 3]
    try:
        reverse_list("bad")
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_01.LL_01_VERSION == "ll-01.v1"
    assert ll_01.SCHEMA_PIN == "northstar.ll-01.v1"
    assert ll_01.stdlib_only() is True
