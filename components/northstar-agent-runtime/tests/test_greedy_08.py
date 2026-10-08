"""Tests for greedy_08 (Jump game II (minimum jumps))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_08
from greedy_08 import min_jumps


def test_01_normal_case():
    assert min_jumps([2, 3, 1, 1, 4]) == 2
    assert min_jumps([2, 3, 0, 1, 4]) == 2


def test_02_edge_cases():
    assert min_jumps([0]) == 0
    assert min_jumps([]) == 0


def test_03_extra():
    assert min_jumps([1, 1, 1, 1]) == 3
    assert min_jumps([5, 1, 1, 1, 1]) == 1


def test_04_version_and_stdlib_only():
    assert greedy_08.GREEDY_08_VERSION == "greedy-08.v1"
    assert greedy_08.stdlib_only() is True
