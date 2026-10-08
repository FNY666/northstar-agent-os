"""Tests for dp_47 (Longest valid parentheses)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_47
from dp_47 import longest_valid


def test_01_normal_case():
    assert longest_valid("(()") == 2
    assert longest_valid(")()())") == 4


def test_02_edge_cases():
    assert longest_valid("") == 0
    assert longest_valid("(((") == 0


def test_03_extra():
    assert longest_valid("()(()") == 2
    assert longest_valid("(()())") == 6


def test_04_version_and_stdlib_only():
    assert dp_47.DP_47_VERSION == "dp-47.v1"
    assert dp_47.stdlib_only() is True
