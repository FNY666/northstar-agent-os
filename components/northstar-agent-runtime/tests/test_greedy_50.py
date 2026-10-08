"""Tests for greedy_50 (Maximum 69 number)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_50
from greedy_50 import maximum_69_number


def test_01_normal_case():
    assert maximum_69_number(9669) == 9969
    assert maximum_69_number(9996) == 9999


def test_02_edge_cases():
    assert maximum_69_number(9999) == 9999
    assert maximum_69_number(6) == 9


def test_03_extra():
    assert maximum_69_number(6969) == 9969
    assert maximum_69_number(66) == 96


def test_04_version_and_stdlib_only():
    assert greedy_50.GREEDY_50_VERSION == "greedy-50.v1"
    assert greedy_50.stdlib_only() is True
