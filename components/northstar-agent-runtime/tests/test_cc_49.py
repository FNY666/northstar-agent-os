"""Tests for cc_49 (Greedy-vs-optimal gap)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_49
from cc_49 import greedy_optimal_gap


def test_01_normal_case():
    assert greedy_optimal_gap(6, [1, 3, 4]) == 1
    assert greedy_optimal_gap(11, [1, 2, 5]) == 0


def test_02_edge_cases():
    assert greedy_optimal_gap(0, [1, 2]) == 0
    assert greedy_optimal_gap(3, [2, 4]) is None


def test_03_extra():
    try:
        greedy_optimal_gap(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # canonical US coins: greedy never loses
    assert all(greedy_optimal_gap(a, [1, 5, 10, 25]) == 0 for a in range(100))


def test_04_version_and_stdlib_only():
    assert cc_49.CC_49_VERSION == "cc-49.v1"
    assert cc_49.stdlib_only() is True
