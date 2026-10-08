"""Tests for ll-46: Merge two lists alternating by node (in-place splice)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_46 as mod


def test_version_and_schema_pin():
    assert mod.LL_46_VERSION == "ll-46.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-46.v1"
    assert mod.stdlib_only() is True


def test_splice_equal():
    out = mod.splice_alternate(mod.from_list([1, 3, 5]), mod.from_list([2, 4, 6]))
    assert mod.to_list(out) == [1, 2, 3, 4, 5, 6]


def test_splice_b_longer():
    out = mod.splice_alternate(mod.from_list([1, 2]), mod.from_list([3, 4, 5, 6]))
    assert mod.to_list(out) == [1, 3, 2, 4, 5, 6]


def test_splice_a_empty():
    assert mod.to_list(mod.splice_alternate(None, mod.from_list([1, 2]))) == [1, 2]
