"""Tests for ll-45: Delete the second half of a singly linked list."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_45 as mod


def test_version_and_schema_pin():
    assert mod.LL_45_VERSION == "ll-45.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-45.v1"
    assert mod.stdlib_only() is True


def test_delete_second_half_odd():
    assert mod.to_list(mod.delete_second_half(mod.from_list([1, 2, 3, 4, 5]))) == [1, 2, 3]


def test_delete_second_half_even():
    assert mod.to_list(mod.delete_second_half(mod.from_list([1, 2, 3, 4]))) == [1, 2]


def test_delete_second_half_empty_raises():
    try:
        mod.delete_second_half(None)
    except mod.LlError:
        return
    raise AssertionError("expected LlError")
