"""Tests for greedy_10 (Minimum arrows to burst balloons)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_10
from greedy_10 import min_arrows


def test_01_normal_case():
    assert min_arrows([[10, 16], [2, 8], [1, 6], [7, 12]]) == 2


def test_02_edge_cases():
    assert min_arrows([]) == 0
    assert min_arrows([[1, 2]]) == 1


def test_03_extra():
    assert min_arrows([[1, 2], [3, 4], [5, 6], [7, 8]]) == 4
    assert min_arrows([[1, 2], [2, 3], [3, 4], [4, 5]]) == 2


def test_04_version_and_stdlib_only():
    assert greedy_10.GREEDY_10_VERSION == "greedy-10.v1"
    assert greedy_10.stdlib_only() is True
