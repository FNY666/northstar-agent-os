"""Tests for greedy_42 (Greedy set cover)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_42
from greedy_42 import greedy_set_cover


def test_01_normal_case():
    assert greedy_set_cover({1, 2, 3, 4, 5}, [{1, 2, 3}, {2, 4}, {3, 4}, {4, 5}]) == [0, 3]


def test_02_edge_cases():
    assert greedy_set_cover(set(), [{1}]) == []
    assert greedy_set_cover({1}, [{1}]) == [0]


def test_03_extra():
    c = greedy_set_cover({1, 2, 3}, [{1}, {2}, {3}, {1, 2, 3}])
    assert c == [3]
    assert greedy_set_cover({9}, [{1}]) == []


def test_04_version_and_stdlib_only():
    assert greedy_42.GREEDY_42_VERSION == "greedy-42.v1"
    assert greedy_42.stdlib_only() is True
