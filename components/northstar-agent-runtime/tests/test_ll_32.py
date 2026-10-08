"""Tests for ll-32: Find the maximum value node of a singly linked list."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_32 as mod


def test_version_and_schema_pin():
    assert mod.LL_32_VERSION == "ll-32.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-32.v1"
    assert mod.stdlib_only() is True


def test_max_mixed():
    assert mod.max_value(mod.from_list([3, 1, 4, 1, 5, 9, 2, 6])) == 9


def test_max_single():
    assert mod.max_value(mod.from_list([42])) == 42


def test_max_empty_raises():
    try:
        mod.max_value(None)
    except mod.LlError:
        return
    raise AssertionError("expected LlError")
