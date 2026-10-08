"""Tests for cc_07 (Feasibility (unbounded supply))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_07
from cc_07 import can_make_change


def test_01_normal_case():
    assert can_make_change(11, [2, 5]) is True
    assert can_make_change(100, [3, 7]) is True


def test_02_edge_cases():
    assert can_make_change(0, [2, 4]) is True
    assert can_make_change(3, [2, 4]) is False
    assert can_make_change(1, [2]) is False


def test_03_extra():
    try:
        can_make_change(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert can_make_change(7, [3, 5]) is False
    assert can_make_change(8, [3, 5]) is True


def test_04_version_and_stdlib_only():
    assert cc_07.CC_07_VERSION == "cc-07.v1"
    assert cc_07.stdlib_only() is True
