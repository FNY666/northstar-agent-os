"""Tests for greedy_23 (Minimum refueling stops)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_23
from greedy_23 import min_refuel_stops


def test_01_normal_case():
    assert min_refuel_stops(100, 10, [[10, 60], [20, 30], [30, 30], [60, 40]]) == 2


def test_02_edge_cases():
    assert min_refuel_stops(1, 1, []) == 0
    assert min_refuel_stops(100, 1, [[10, 100]]) == -1


def test_03_extra():
    assert min_refuel_stops(100, 50, [[50, 50]]) == 1
    assert min_refuel_stops(10, 10, []) == 0


def test_04_version_and_stdlib_only():
    assert greedy_23.GREEDY_23_VERSION == "greedy-23.v1"
    assert greedy_23.stdlib_only() is True
