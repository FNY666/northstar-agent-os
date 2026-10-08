"""Tests for ll-35: Delete the first occurrence of a value."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_35 as mod


def test_version_and_schema_pin():
    assert mod.LL_35_VERSION == "ll-35.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-35.v1"
    assert mod.stdlib_only() is True


def test_delete_first_middle():
    head, ok = mod.delete_first(mod.from_list([1, 2, 3, 2]), 2)
    assert ok is True
    assert mod.to_list(head) == [1, 3, 2]


def test_delete_first_missing():
    head, ok = mod.delete_first(mod.from_list([1, 2, 3]), 99)
    assert ok is False
    assert mod.to_list(head) == [1, 2, 3]


def test_delete_first_empty():
    head, ok = mod.delete_first(None, 1)
    assert ok is False
    assert head is None
