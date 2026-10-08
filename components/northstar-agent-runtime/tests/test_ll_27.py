"""Tests for ll-27: Split a list into two halves."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_27 as mod


def test_version_and_schema_pin():
    assert mod.LL_27_VERSION == "ll-27.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-27.v1"
    assert mod.stdlib_only() is True


def test_split_even():
    a, b = mod.split_halves(mod.from_list([1, 2, 3, 4, 5, 6]))
    assert mod.to_list(a) == [1, 2, 3]
    assert mod.to_list(b) == [4, 5, 6]


def test_split_odd_second_gets_extra():
    a, b = mod.split_halves(mod.from_list([1, 2, 3, 4, 5]))
    assert mod.to_list(a) == [1, 2]
    assert mod.to_list(b) == [3, 4, 5]


def test_split_none_raises():
    try:
        mod.split_halves(None)
    except mod.LlError:
        return
    raise AssertionError("expected LlError")
