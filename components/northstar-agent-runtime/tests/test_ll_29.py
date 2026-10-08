"""Tests for ll-29: Count the nodes of a singly linked list."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_29 as mod


def test_version_and_schema_pin():
    assert mod.LL_29_VERSION == "ll-29.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-29.v1"
    assert mod.stdlib_only() is True


def test_count_empty():
    assert mod.count_nodes(None) == 0


def test_count_five():
    assert mod.count_nodes(mod.from_list([1, 2, 3, 4, 5])) == 5


def test_count_cycle_raises():
    h = mod.from_list([1, 2, 3])
    tail = h
    while tail.next is not None:
        tail = tail.next
    tail.next = h
    try:
        mod.count_nodes(h)
    except mod.LlError:
        return
    raise AssertionError("expected LlError")
