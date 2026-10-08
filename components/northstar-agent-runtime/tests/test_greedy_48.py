"""Tests for greedy_48 (Two city scheduling)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_48
from greedy_48 import two_city_cost


def test_01_normal_case():
    assert two_city_cost([[10, 20], [30, 200], [400, 50], [30, 20]]) == 110


def test_02_edge_cases():
    assert two_city_cost([]) == 0
    assert two_city_cost([[10, 10], [10, 10]]) == 20


def test_03_extra():
    assert two_city_cost([[259, 770], [448, 54], [926, 667], [184, 139], [840, 118], [577, 469]]) == 1859
    assert two_city_cost([[1, 2], [3, 4]]) == 5


def test_04_version_and_stdlib_only():
    assert greedy_48.GREEDY_48_VERSION == "greedy-48.v1"
    assert greedy_48.stdlib_only() is True
