"""Tests for ll-34: Insert a value at the head and at the tail."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_34 as mod


def test_version_and_schema_pin():
    assert mod.LL_34_VERSION == "ll-34.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-34.v1"
    assert mod.stdlib_only() is True


def test_insert_head():
    assert mod.to_list(mod.insert_head(mod.from_list([2, 3]), 1)) == [1, 2, 3]


def test_insert_tail():
    assert mod.to_list(mod.insert_tail(mod.from_list([1, 2]), 3)) == [1, 2, 3]


def test_insert_tail_empty():
    assert mod.to_list(mod.insert_tail(None, 5)) == [5]


def test_insert_none_value_raises():
    try:
        mod.insert_tail(None, None)
    except mod.LlError:
        return
    raise AssertionError("expected LlError")
