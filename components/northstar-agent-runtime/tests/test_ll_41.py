"""Tests for ll-41: Insertion sort on a singly linked list."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_41 as mod


def test_version_and_schema_pin():
    assert mod.LL_41_VERSION == "ll-41.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-41.v1"
    assert mod.stdlib_only() is True


def test_insertion_sort_unsorted():
    assert mod.to_list(mod.insertion_sort(mod.from_list([4, 2, 1, 3]))) == [1, 2, 3, 4]


def test_insertion_sort_reversed():
    assert mod.to_list(mod.insertion_sort(mod.from_list([5, 4, 3, 2, 1]))) == [1, 2, 3, 4, 5]


def test_insertion_sort_empty():
    assert mod.to_list(mod.insertion_sort(None)) == []
