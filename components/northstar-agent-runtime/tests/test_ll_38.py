"""Tests for ll-38: Insert a value into a sorted circular linked list."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_38 as mod


def test_version_and_schema_pin():
    assert mod.LL_38_VERSION == "ll-38.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-38.v1"
    assert mod.stdlib_only() is True


def test_circular_insert_empty():
    h = mod.circular_insert(None, 5)
    assert mod.to_circular_list(h) == [5]
    assert h.next is h


def test_circular_insert_sorted():
    h = mod.circular_insert(mod.make_circular([1, 3, 4]), 2)
    assert mod.to_circular_list(h) == [1, 2, 3, 4]


def test_circular_insert_linear_raises():
    try:
        mod.circular_insert(mod.from_list([1, 2, 3]), 4)
    except mod.LlError:
        return
    raise AssertionError("expected LlError")
