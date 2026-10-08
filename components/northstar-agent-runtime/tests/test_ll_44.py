"""Tests for ll-44: Doubly linked list to array roundtrip."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_44 as mod


def test_version_and_schema_pin():
    assert mod.LL_44_VERSION == "ll-44.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-44.v1"
    assert mod.stdlib_only() is True


def test_doubly_roundtrip():
    assert mod.d_roundtrip([1, 2, 3, 4]) == [1, 2, 3, 4]


def test_doubly_roundtrip_empty():
    assert mod.d_roundtrip([]) == []


def test_doubly_prev_links_consistent():
    h = mod.d_from_array([1, 2, 3])
    cur = h
    prev = None
    while cur is not None:
        assert cur.prev is prev
        prev = cur
        cur = cur.next
