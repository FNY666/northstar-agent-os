"""Tests for greedy_32 (Course schedule III)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_32
from greedy_32 import schedule_courses


def test_01_normal_case():
    assert schedule_courses([[100, 200], [200, 1300], [1000, 1250], [2000, 3200]]) == 3


def test_02_edge_cases():
    assert schedule_courses([]) == 0
    assert schedule_courses([[3, 2], [4, 3]]) == 0


def test_03_extra():
    assert schedule_courses([[1, 2]]) == 1
    assert schedule_courses([[5, 5], [4, 6], [2, 6]]) == 2


def test_04_version_and_stdlib_only():
    assert greedy_32.GREEDY_32_VERSION == "greedy-32.v1"
    assert greedy_32.stdlib_only() is True
