"""Tests for ll-49: Collect node values in reverse order (reverse print)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_49 as mod


def test_version_and_schema_pin():
    assert mod.LL_49_VERSION == "ll-49.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-49.v1"
    assert mod.stdlib_only() is True


def test_reverse_values_basic():
    assert mod.reverse_values(mod.from_list([1, 2, 3])) == [3, 2, 1]


def test_reverse_values_empty():
    assert mod.reverse_values(None) == []


def test_reverse_values_list_untouched():
    h = mod.from_list([1, 2, 3])
    mod.reverse_values(h)
    assert mod.to_list(h) == [1, 2, 3]
