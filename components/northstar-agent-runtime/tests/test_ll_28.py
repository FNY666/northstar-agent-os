"""Tests for ll-28: Zip-merge two lists alternating their nodes."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_28 as mod


def test_version_and_schema_pin():
    assert mod.LL_28_VERSION == "ll-28.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-28.v1"
    assert mod.stdlib_only() is True


def test_zip_even():
    out = mod.zip_merge(mod.from_list([1, 3, 5]), mod.from_list([2, 4, 6]))
    assert mod.to_list(out) == [1, 2, 3, 4, 5, 6]


def test_zip_uneven():
    out = mod.zip_merge(mod.from_list([1, 2]), mod.from_list([3]))
    assert mod.to_list(out) == [1, 3, 2]


def test_zip_both_empty():
    assert mod.to_list(mod.zip_merge(None, None)) == []


def test_zip_inputs_not_mutated():
    a = mod.from_list([1, 2])
    b = mod.from_list([3])
    mod.zip_merge(a, b)
    assert mod.to_list(a) == [1, 2]
    assert mod.to_list(b) == [3]
