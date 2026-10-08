"""Tests for greedy_35 (Car fleet)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_35
from greedy_35 import car_fleet


def test_01_normal_case():
    assert car_fleet(12, [10, 8, 0, 5, 3], [2, 4, 1, 1, 3]) == 3


def test_02_edge_cases():
    assert car_fleet(10, [], []) == 0
    assert car_fleet(10, [3], [3]) == 1


def test_03_extra():
    assert car_fleet(100, [0, 2, 4], [4, 2, 1]) == 1
    assert car_fleet(10, [6, 8], [3, 2]) == 2


def test_04_version_and_stdlib_only():
    assert greedy_35.GREEDY_35_VERSION == "greedy-35.v1"
    assert greedy_35.stdlib_only() is True
