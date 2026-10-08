"""Tests for dp_35 (Jump game II (minimum jumps))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_35
from dp_35 import min_jumps


def test_01_normal_case():
    assert min_jumps([2, 3, 1, 1, 4]) == 2
    assert min_jumps([2, 3, 0, 1, 4]) == 2


def test_02_edge_cases():
    assert min_jumps([1]) == 0
    assert min_jumps([]) == 0


def test_03_extra():
    assert min_jumps([1, 2, 3]) == 2
    assert min_jumps([3, 2, 1, 1, 4]) == 2


def test_04_version_and_stdlib_only():
    assert dp_35.DP_35_VERSION == "dp-35.v1"
    assert dp_35.stdlib_only() is True
