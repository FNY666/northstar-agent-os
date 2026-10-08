"""Tests for ll-26: Delete the middle node of a singly linked list."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_26 as mod


def test_version_and_schema_pin():
    assert mod.LL_26_VERSION == "ll-26.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-26.v1"
    assert mod.stdlib_only() is True


def test_delete_middle_odd():
    assert mod.to_list(mod.delete_middle(mod.from_list([1, 2, 3, 4, 5]))) == [1, 2, 4, 5]


def test_delete_middle_even():
    assert mod.to_list(mod.delete_middle(mod.from_list([1, 2, 3, 4]))) == [1, 2, 4]


def test_delete_middle_single_raises():
    try:
        mod.delete_middle(mod.from_list([9]))
    except mod.LlError:
        return
    raise AssertionError("expected LlError")


def test_delete_middle_none_raises():
    try:
        mod.delete_middle(None)
    except mod.LlError:
        return
    raise AssertionError("expected LlError")
