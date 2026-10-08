"""Tests for algo_45: Levenshtein edit distance."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import algo_45 as a45
from algo_45 import edit_distance


def test_version_pin_and_stdlib_only():
    assert a45.ALGO_45_VERSION == "algo-45.v1"
    assert a45.stdlib_only() is True


def test_edit_distance_classic():
    assert edit_distance("kitten", "sitting") == 3


def test_edit_distance_edge_cases():
    assert edit_distance("", "") == 0
    assert edit_distance("abc", "") == 3
    assert edit_distance("", "xyz") == 3
    assert edit_distance("abc", "abc") == 0


def test_edit_distance_properties():
    assert edit_distance("a", "b") == 1
    assert edit_distance("flaw", "lawn") == 2
    # symmetric and bounded by max length
    a, b = "intention", "execution"
    assert edit_distance(a, b) == edit_distance(b, a)
    assert edit_distance(a, b) <= max(len(a), len(b))
