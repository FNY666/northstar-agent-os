"""Tests for ll-36: Doubly linked list: insert, delete, and traverse."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_36 as mod


def test_version_and_schema_pin():
    assert mod.LL_36_VERSION == "ll-36.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-36.v1"
    assert mod.stdlib_only() is True


def test_doubly_traverse_both_ways():
    h = mod.d_from_list([1, 2, 3])
    assert mod.d_to_list(h) == [1, 2, 3]
    assert mod.d_to_list_backward(h) == [3, 2, 1]


def test_doubly_insert_delete():
    h = mod.d_insert_tail(mod.d_from_list([1, 2]), 3)
    assert mod.d_to_list(h) == [1, 2, 3]
    h, ok = mod.d_delete_first(h, 2)
    assert ok is True
    assert mod.d_to_list(h) == [1, 3]
    assert mod.d_to_list_backward(h) == [3, 1]


def test_doubly_prev_links_consistent():
    h = mod.d_from_list([1, 2, 3])
    cur = h
    prev = None
    while cur is not None:
        assert cur.prev is prev
        prev = cur
        cur = cur.next
