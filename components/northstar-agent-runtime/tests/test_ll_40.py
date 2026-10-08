"""Tests for ll-40: Split a list into k parts."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_40 as mod


def test_version_and_schema_pin():
    assert mod.LL_40_VERSION == "ll-40.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-40.v1"
    assert mod.stdlib_only() is True


def test_split_k_three():
    parts = mod.split_k(mod.from_list([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), 3)
    assert [mod.to_list(p) for p in parts] == [[1, 2, 3, 4], [5, 6, 7], [8, 9, 10]]


def test_split_k_more_parts_than_nodes():
    parts = mod.split_k(mod.from_list([1, 2, 3]), 5)
    assert [mod.to_list(p) for p in parts] == [[1], [2], [3], [], []]


def test_split_k_invalid_raises():
    try:
        mod.split_k(mod.from_list([1]), 0)
    except mod.LlError:
        return
    raise AssertionError("expected LlError")
