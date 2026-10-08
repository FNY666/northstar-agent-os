"""Tests for ll-39: Compare two singly linked lists for equality."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_39 as mod


def test_version_and_schema_pin():
    assert mod.LL_39_VERSION == "ll-39.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-39.v1"
    assert mod.stdlib_only() is True


def test_equal_lists():
    assert mod.lists_equal(mod.from_list([1, 2, 3]), mod.from_list([1, 2, 3])) is True


def test_different_length():
    assert mod.lists_equal(mod.from_list([1, 2]), mod.from_list([1, 2, 3])) is False


def test_both_empty():
    assert mod.lists_equal(None, None) is True
