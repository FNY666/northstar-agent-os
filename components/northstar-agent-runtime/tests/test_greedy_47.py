"""Tests for greedy_47 (Broken calculator)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_47
from greedy_47 import broken_calc


def test_01_normal_case():
    assert broken_calc(2, 3) == 2
    assert broken_calc(5, 8) == 2


def test_02_edge_cases():
    assert broken_calc(3, 3) == 0
    assert broken_calc(1024, 1) == 1023


def test_03_extra():
    assert broken_calc(3, 10) == 3
    assert broken_calc(1, 1000000000) == 39


def test_04_version_and_stdlib_only():
    assert greedy_47.GREEDY_47_VERSION == "greedy-47.v1"
    assert greedy_47.stdlib_only() is True
