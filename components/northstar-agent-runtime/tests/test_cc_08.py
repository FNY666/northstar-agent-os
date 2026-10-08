"""Tests for cc_08 (Feasibility (bounded supply))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_08
from cc_08 import can_make_change_bounded


def test_01_normal_case():
    assert can_make_change_bounded(7, [(5, 1), (2, 1)]) is True
    assert can_make_change_bounded(10, [(5, 2)]) is True


def test_02_edge_cases():
    assert can_make_change_bounded(0, []) is True
    assert can_make_change_bounded(7, [(5, 1)]) is False
    assert can_make_change_bounded(9, [(5, 1), (2, 1)]) is False


def test_03_extra():
    try:
        can_make_change_bounded(-1, [(1, 1)])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert can_make_change_bounded(6, [(4, 1), (1, 10)]) is True


def test_04_version_and_stdlib_only():
    assert cc_08.CC_08_VERSION == "cc-08.v1"
    assert cc_08.stdlib_only() is True
