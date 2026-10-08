"""Tests for ll-30: Find the kth node from the end of the list."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_30 as mod


def test_version_and_schema_pin():
    assert mod.LL_30_VERSION == "ll-30.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-30.v1"
    assert mod.stdlib_only() is True


def test_kth_from_end_middle():
    assert mod.kth_from_end(mod.from_list([1, 2, 3, 4, 5]), 2) == 4


def test_kth_from_end_is_length():
    assert mod.kth_from_end(mod.from_list([7, 8, 9]), 3) == 7


def test_kth_too_large_raises():
    try:
        mod.kth_from_end(mod.from_list([1, 2]), 3)
    except mod.LlError:
        return
    raise AssertionError("expected LlError")
