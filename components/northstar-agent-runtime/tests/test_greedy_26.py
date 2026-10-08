"""Tests for greedy_26 (Largest number arrangement)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_26
from greedy_26 import largest_number


def test_01_normal_case():
    assert largest_number([10, 2]) == "210"
    assert largest_number([3, 30, 34, 5, 9]) == "9534330"


def test_02_edge_cases():
    assert largest_number([0, 0]) == "0"
    assert largest_number([]) == "0"


def test_03_extra():
    assert largest_number([1]) == "1"
    assert largest_number([20, 1]) == "201"


def test_04_version_and_stdlib_only():
    assert greedy_26.GREEDY_26_VERSION == "greedy-26.v1"
    assert greedy_26.stdlib_only() is True
