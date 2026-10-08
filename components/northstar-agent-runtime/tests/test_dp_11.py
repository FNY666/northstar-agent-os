"""Tests for dp_11 (Edit distance (Levenshtein))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_11
from dp_11 import edit_distance


def test_01_normal_case():
    assert edit_distance("horse", "ros") == 3
    assert edit_distance("intention", "execution") == 5


def test_02_edge_cases():
    assert edit_distance("", "") == 0
    assert edit_distance("abc", "abc") == 0


def test_03_extra():
    assert edit_distance("kitten", "sitting") == 3
    assert edit_distance("a", "b") == 1


def test_04_version_and_stdlib_only():
    assert dp_11.DP_11_VERSION == "dp-11.v1"
    assert dp_11.stdlib_only() is True
