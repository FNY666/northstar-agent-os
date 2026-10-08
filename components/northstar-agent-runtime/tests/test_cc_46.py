"""Tests for cc_46 (Count sequences with no adjacent equal coins)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_46
from cc_46 import count_sequences_no_adjacent


def test_01_normal_case():
    assert count_sequences_no_adjacent(3, [1, 2]) == 2
    assert count_sequences_no_adjacent(4, [1, 2]) == 2


def test_02_edge_cases():
    assert count_sequences_no_adjacent(0, [1]) == 1
    assert count_sequences_no_adjacent(2, [1, 2]) == 1
    assert count_sequences_no_adjacent(1, [2]) == 0


def test_03_extra():
    try:
        count_sequences_no_adjacent(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # single denomination: only length-1 sequences qualify
    assert count_sequences_no_adjacent(5, [5]) == 1
    assert count_sequences_no_adjacent(10, [5]) == 0


def test_04_version_and_stdlib_only():
    assert cc_46.CC_46_VERSION == "cc-46.v1"
    assert cc_46.stdlib_only() is True
