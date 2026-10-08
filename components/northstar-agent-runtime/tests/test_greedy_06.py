"""Tests for greedy_06 (Gas station circuit)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_06
from greedy_06 import gas_station


def test_01_normal_case():
    assert gas_station([1, 2, 3, 4, 5], [3, 4, 5, 1, 2]) == 3


def test_02_edge_cases():
    assert gas_station([2, 3, 4], [3, 4, 3]) == -1
    assert gas_station([5], [4]) == 0


def test_03_extra():
    assert gas_station([3], [5]) == -1
    assert gas_station([4, 5, 2, 6, 3], [3, 2, 7, 3, 2]) == 3


def test_04_version_and_stdlib_only():
    assert greedy_06.GREEDY_06_VERSION == "greedy-06.v1"
    assert greedy_06.stdlib_only() is True
