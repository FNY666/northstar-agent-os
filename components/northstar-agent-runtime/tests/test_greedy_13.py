"""Tests for greedy_13 (Minimum platforms)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_13
from greedy_13 import min_platforms


def test_01_normal_case():
    assert min_platforms([900, 940, 950, 1100, 1500, 1800], [910, 1200, 1120, 1130, 1900, 2000]) == 3


def test_02_edge_cases():
    assert min_platforms([], []) == 0
    assert min_platforms([900], [1000]) == 1


def test_03_extra():
    assert min_platforms([900, 1000], [930, 1100]) == 1
    assert min_platforms([900, 900], [900, 900]) == 2


def test_04_version_and_stdlib_only():
    assert greedy_13.GREEDY_13_VERSION == "greedy-13.v1"
    assert greedy_13.stdlib_only() is True
