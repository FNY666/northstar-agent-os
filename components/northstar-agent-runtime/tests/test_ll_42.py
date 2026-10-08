"""Tests for ll-42: Remove a cycle from a singly linked list (break the loop)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_42 as mod


def test_version_and_schema_pin():
    assert mod.LL_42_VERSION == "ll-42.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-42.v1"
    assert mod.stdlib_only() is True


def test_removes_tail_cycle():
    h = mod.remove_cycle(mod.make_cycle(mod.from_list([1, 2, 3]), 0))
    assert mod.to_list(h) == [1, 2, 3]


def test_no_cycle_unchanged():
    assert mod.to_list(mod.remove_cycle(mod.from_list([1, 2, 3]))) == [1, 2, 3]


def test_empty():
    assert mod.remove_cycle(None) is None
