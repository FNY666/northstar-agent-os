"""Tests for cc_48 (Largest unformable amount)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_48
from cc_48 import largest_unformable


def test_01_normal_case():
    assert largest_unformable([3, 5]) == 7
    assert largest_unformable([4, 7]) == 17


def test_02_edge_cases():
    assert largest_unformable([1, 2, 5]) == -1
    assert largest_unformable([6, 10, 15]) == 29


def test_03_extra():
    try:
        largest_unformable([4, 6])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    try:
        largest_unformable([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert cc_48.CC_48_VERSION == "cc-48.v1"
    assert cc_48.stdlib_only() is True
