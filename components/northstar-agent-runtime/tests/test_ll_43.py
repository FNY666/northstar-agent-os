"""Tests for ll-43: Reverse a doubly linked list."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_43 as mod


def test_version_and_schema_pin():
    assert mod.LL_43_VERSION == "ll-43.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-43.v1"
    assert mod.stdlib_only() is True


def test_reverse_doubly():
    h = mod.d_reverse(mod.d_from_list([1, 2, 3]))
    assert mod.d_to_list(h) == [3, 2, 1]
    assert mod.d_to_list_backward(h) == [1, 2, 3]


def test_reverse_doubly_single():
    assert mod.d_to_list(mod.d_reverse(mod.d_from_list([7]))) == [7]


def test_reverse_doubly_empty():
    assert mod.d_reverse(None) is None
