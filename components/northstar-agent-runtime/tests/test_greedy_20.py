"""Tests for greedy_20 (Task scheduler)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_20
from greedy_20 import least_interval


def test_01_normal_case():
    assert least_interval(["A", "A", "A", "B", "B", "B"], 2) == 8


def test_02_edge_cases():
    assert least_interval([], 2) == 0
    assert least_interval(["A"], 5) == 1


def test_03_extra():
    assert least_interval(["A", "A", "A", "B", "B", "B"], 0) == 6
    assert least_interval(["A", "A", "A", "A", "A", "A", "B", "C", "D", "E", "F", "G"], 2) == 16


def test_04_version_and_stdlib_only():
    assert greedy_20.GREEDY_20_VERSION == "greedy-20.v1"
    assert greedy_20.stdlib_only() is True
