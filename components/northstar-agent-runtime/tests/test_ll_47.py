"""Tests for ll-47: Remove all nodes with a value greater than x."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_47 as mod


def test_version_and_schema_pin():
    assert mod.LL_47_VERSION == "ll-47.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-47.v1"
    assert mod.stdlib_only() is True


def test_remove_greater_some():
    assert mod.to_list(mod.remove_greater(mod.from_list([1, 5, 2, 8, 3]), 4)) == [1, 2, 3]


def test_remove_greater_all():
    assert mod.to_list(mod.remove_greater(mod.from_list([5, 6, 7]), 4)) == []


def test_remove_greater_bad_x_raises():
    try:
        mod.remove_greater(mod.from_list([1, 2]), "x")
    except mod.LlError:
        return
    raise AssertionError("expected LlError")
