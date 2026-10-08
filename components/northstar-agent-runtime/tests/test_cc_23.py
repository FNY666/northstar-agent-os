"""Tests for cc_23 (Feasibility via memoized recursion)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_23
from cc_23 import can_make_change_memo


def test_01_normal_case():
    assert can_make_change_memo(11, [1, 2, 5]) is True
    assert can_make_change_memo(100, [3, 7]) is True


def test_02_edge_cases():
    assert can_make_change_memo(0, [2]) is True
    assert can_make_change_memo(3, [2, 4]) is False


def test_03_extra():
    try:
        can_make_change_memo(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert can_make_change_memo(7, [3, 5]) is False


def test_04_version_and_stdlib_only():
    assert cc_23.CC_23_VERSION == "cc-23.v1"
    assert cc_23.stdlib_only() is True
