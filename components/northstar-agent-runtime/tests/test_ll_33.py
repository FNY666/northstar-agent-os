"""Tests for ll-33: Search a singly linked list for a value."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_33 as mod


def test_version_and_schema_pin():
    assert mod.LL_33_VERSION == "ll-33.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-33.v1"
    assert mod.stdlib_only() is True


def test_search_found():
    assert mod.search(mod.from_list([10, 20, 30]), 20) == 1


def test_search_missing():
    assert mod.search(mod.from_list([10, 20, 30]), 99) == -1


def test_search_empty():
    assert mod.search(None, 1) == -1
