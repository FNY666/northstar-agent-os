"""Tests for greedy_37 (Minimize maximum lateness (EDD))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_37
from greedy_37 import min_max_lateness


def test_01_normal_case():
    assert min_max_lateness([(3, 6), (2, 8), (1, 9), (4, 9), (3, 14), (2, 15)]) == 1


def test_02_edge_cases():
    assert min_max_lateness([]) == 0
    assert min_max_lateness([(1, 1)]) == 0


def test_03_extra():
    assert min_max_lateness([(5, 3)]) == 2
    assert min_max_lateness([(2, 2), (2, 2)]) == 2


def test_04_version_and_stdlib_only():
    assert greedy_37.GREEDY_37_VERSION == "greedy-37.v1"
    assert greedy_37.stdlib_only() is True
