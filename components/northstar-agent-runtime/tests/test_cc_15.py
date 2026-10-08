"""Tests for cc_15 (Exact-k coins reconstruction)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_15
from cc_15 import coins_with_exact_k


def test_01_normal_case():
    assert coins_with_exact_k(11, [1, 2, 5], 3) == [1, 5, 5]
    assert coins_with_exact_k(10, [1, 2, 5], 2) == [5, 5]


def test_02_edge_cases():
    assert coins_with_exact_k(0, [1], 0) == []
    assert coins_with_exact_k(11, [1, 2, 5], 2) is None
    assert coins_with_exact_k(5, [2], 1) is None


def test_03_extra():
    try:
        coins_with_exact_k(-1, [1], 1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    out = coins_with_exact_k(6, [1, 3, 4], 3)
    assert out is not None and sum(out) == 6 and len(out) == 3


def test_04_version_and_stdlib_only():
    assert cc_15.CC_15_VERSION == "cc-15.v1"
    assert cc_15.stdlib_only() is True
