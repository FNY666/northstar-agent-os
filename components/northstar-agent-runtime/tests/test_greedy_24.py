"""Tests for greedy_24 (Candy distribution)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_24
from greedy_24 import candy


def test_01_normal_case():
    assert candy([1, 0, 2]) == 5
    assert candy([1, 2, 2]) == 4


def test_02_edge_cases():
    assert candy([]) == 0
    assert candy([5]) == 1


def test_03_extra():
    assert candy([1, 3, 4, 5, 2]) == 11
    assert candy([1, 3, 2]) == 4


def test_04_version_and_stdlib_only():
    assert greedy_24.GREEDY_24_VERSION == "greedy-24.v1"
    assert greedy_24.stdlib_only() is True
