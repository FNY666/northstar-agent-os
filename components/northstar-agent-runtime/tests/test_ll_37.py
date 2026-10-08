"""Tests for ll-37: Detect a cycle in a singly linked list."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_37 as mod


def test_version_and_schema_pin():
    assert mod.LL_37_VERSION == "ll-37.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-37.v1"
    assert mod.stdlib_only() is True


def test_detects_cycle():
    h = mod.make_cycle(mod.from_list([1, 2, 3]), 0)
    assert mod.has_cycle(h) is True


def test_no_cycle():
    assert mod.has_cycle(mod.from_list([1, 2, 3])) is False


def test_cycle_entry_value():
    h = mod.make_cycle(mod.from_list([1, 2, 3, 4]), 2)
    assert mod.cycle_entry_value(h) == 3
    assert mod.cycle_entry_value(mod.from_list([1, 2])) is None
