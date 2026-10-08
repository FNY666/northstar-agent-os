"""Tests for dp_42 (Maximum length of pair chain)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_42
from dp_42 import pair_chain


def test_01_normal_case():
    assert pair_chain([[1, 2], [2, 3], [3, 4]]) == 2
    assert pair_chain([[1, 2], [7, 8], [4, 5]]) == 3


def test_02_edge_cases():
    assert pair_chain([]) == 0
    assert pair_chain([[5, 6]]) == 1


def test_03_extra():
    assert pair_chain([[-6, -5], [-4, -3], [-2, -1]]) == 3
    assert pair_chain([[1, 10], [2, 3], [4, 5], [6, 7]]) == 3


def test_04_version_and_stdlib_only():
    assert dp_42.DP_42_VERSION == "dp-42.v1"
    assert dp_42.stdlib_only() is True
