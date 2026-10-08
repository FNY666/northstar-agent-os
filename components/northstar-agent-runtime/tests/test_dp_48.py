"""Tests for dp_48 (Maximal square)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_48
from dp_48 import maximal_square


def test_01_normal_case():
    assert maximal_square([["1", "0", "1", "0", "0"],
                             ["1", "0", "1", "1", "1"],
                             ["1", "1", "1", "1", "1"],
                             ["1", "0", "0", "1", "0"]]) == 4


def test_02_edge_cases():
    assert maximal_square([]) == 0
    assert maximal_square([["0"]]) == 0


def test_03_extra():
    assert maximal_square([["1", "1", "1"],
                             ["1", "1", "1"],
                             ["1", "1", "1"]]) == 9
    assert maximal_square([["1", "0"], ["0", "1"]]) == 1


def test_04_version_and_stdlib_only():
    assert dp_48.DP_48_VERSION == "dp-48.v1"
    assert dp_48.stdlib_only() is True
