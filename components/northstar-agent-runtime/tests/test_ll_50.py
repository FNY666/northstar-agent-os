"""Tests for ll-50: Array to linked list roundtrip."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ll_50 as mod


def test_version_and_schema_pin():
    assert mod.LL_50_VERSION == "ll-50.v1"
    assert mod.SCHEMA_PIN == "northstar.ll-50.v1"
    assert mod.stdlib_only() is True


def test_roundtrip_ints():
    assert mod.array_roundtrip([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]


def test_roundtrip_empty():
    assert mod.array_roundtrip([]) == []


def test_roundtrip_none_raises():
    try:
        mod.array_roundtrip(None)
    except mod.LlError:
        return
    raise AssertionError("expected LlError")
