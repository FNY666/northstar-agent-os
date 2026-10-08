"""Tests for ll-31: Sum all values of a singly linked list."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_31 as mod


def test_version_and_schema_pin():
    assert mod.LL_31_VERSION == "ll-31.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-31.v1"
    assert mod.stdlib_only() is True


def test_sum_ints():
    assert mod.sum_values(mod.from_list([1, 2, 3, 4])) == 10


def test_sum_empty():
    assert mod.sum_values(None) == 0


def test_sum_non_numeric_raises():
    try:
        mod.sum_values(mod.from_list(["a"]))
    except mod.LlError:
        return
    raise AssertionError("expected LlError")
