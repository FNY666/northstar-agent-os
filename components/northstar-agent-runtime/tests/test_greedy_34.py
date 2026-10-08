"""Tests for greedy_34 (Advantage shuffle)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_34
from greedy_34 import advantage_shuffle


def test_01_normal_case():
    r = advantage_shuffle([2, 7, 11, 15], [1, 10, 4, 11])
    assert sorted(r) == [2, 7, 11, 15]
    assert sum(1 for a, b in zip(r, [1, 10, 4, 11]) if a > b) == 4


def test_02_edge_cases():
    assert advantage_shuffle([5], [5]) == [5]
    assert advantage_shuffle([], []) == []


def test_03_extra():
    assert advantage_shuffle([12, 24, 8, 32], [13, 25, 32, 11]) == [24, 32, 8, 12]


def test_04_version_and_stdlib_only():
    assert greedy_34.GREEDY_34_VERSION == "greedy-34.v1"
    assert greedy_34.stdlib_only() is True
