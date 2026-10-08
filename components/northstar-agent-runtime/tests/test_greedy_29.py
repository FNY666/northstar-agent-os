"""Tests for greedy_29 (Minimum cost to connect sticks)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_29
from greedy_29 import connect_sticks


def test_01_normal_case():
    assert connect_sticks([2, 4, 3]) == 14
    assert connect_sticks([1, 8, 3, 5]) == 30


def test_02_edge_cases():
    assert connect_sticks([]) == 0
    assert connect_sticks([5]) == 0


def test_03_extra():
    assert connect_sticks([1, 1, 1, 1]) == 8
    assert connect_sticks([5, 4, 3, 2, 1]) == 33


def test_04_version_and_stdlib_only():
    assert greedy_29.GREEDY_29_VERSION == "greedy-29.v1"
    assert greedy_29.stdlib_only() is True
