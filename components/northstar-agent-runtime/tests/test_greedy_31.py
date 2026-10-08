"""Tests for greedy_31 (IPO (maximize capital))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_31
from greedy_31 import maximize_capital


def test_01_normal_case():
    assert maximize_capital(2, 0, [1, 2, 3], [0, 1, 1]) == 4
    assert maximize_capital(3, 0, [1, 2, 3], [0, 1, 2]) == 6


def test_02_edge_cases():
    assert maximize_capital(1, 0, [5], [10]) == 0
    assert maximize_capital(0, 7, [1], [0]) == 7


def test_03_extra():
    assert maximize_capital(2, 0, [1, 2, 3], [0, 1, 1]) == 4
    assert maximize_capital(10, 0, [1, 2], [0, 0]) == 3


def test_04_version_and_stdlib_only():
    assert greedy_31.GREEDY_31_VERSION == "greedy-31.v1"
    assert greedy_31.stdlib_only() is True
