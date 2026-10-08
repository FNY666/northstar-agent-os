"""Tests for ll-48: Intersection of two lists by value (common values)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_48 as mod


def test_version_and_schema_pin():
    assert mod.LL_48_VERSION == "ll-48.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-48.v1"
    assert mod.stdlib_only() is True


def test_intersect_some():
    assert mod.intersect_values(mod.from_list([1, 2, 3, 4]), mod.from_list([3, 4, 5])) == [3, 4]


def test_intersect_none():
    assert mod.intersect_values(mod.from_list([1, 2]), mod.from_list([3, 4])) == []


def test_intersect_dedup():
    assert mod.intersect_values(mod.from_list([1, 1, 2, 2]), mod.from_list([2])) == [2]
