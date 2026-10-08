"""Tests for ll_25 (reverse sublist between positions m and n)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_25
from ll_25 import reverse_between, from_list, to_list, LlError


def test_01_normal_case():
    assert to_list(reverse_between(from_list([1, 2, 3, 4, 5]), 2, 4)) == [1, 4, 3, 2, 5]
    assert to_list(reverse_between(from_list([1, 2, 3, 4, 5]), 1, 5)) == [5, 4, 3, 2, 1]
    assert to_list(reverse_between(from_list([1, 2, 3]), 1, 2)) == [2, 1, 3]


def test_02_edge_cases():
    assert to_list(reverse_between(from_list([1, 2, 3]), 2, 2)) == [1, 2, 3]
    assert to_list(reverse_between(from_list([9]), 1, 1)) == [9]
    assert to_list(reverse_between(from_list([1, 2, 3]), 2, 3)) == [1, 3, 2]


def test_03_extra():
    assert to_list(reverse_between(from_list([1, 2, 3, 4]), 1, 3)) == [3, 2, 1, 4]
    for m, n in ((3, 2), (0, 2), (1, 6), (True, 2), (1.5, 2)):
        try:
            reverse_between(from_list([1, 2, 3, 4, 5]), m, n)
            raised = False
        except LlError:
            raised = True
        assert raised is True, f"m={m!r}, n={n!r} should raise"


def test_04_version_and_stdlib_only():
    assert ll_25.LL_25_VERSION == "ll-25.v1"
    assert ll_25.SCHEMA_PIN == "northstar.ll-25.v1"
    assert ll_25.stdlib_only() is True
