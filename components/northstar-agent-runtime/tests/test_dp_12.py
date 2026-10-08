"""Tests for dp_12 (Palindrome partitioning (minimum cuts))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_12
from dp_12 import min_cuts


def test_01_normal_case():
    assert min_cuts("aab") == 1
    assert min_cuts("abccbc") == 2


def test_02_edge_cases():
    assert min_cuts("") == 0
    assert min_cuts("a") == 0
    assert min_cuts("aba") == 0


def test_03_extra():
    assert min_cuts("aaabbb") == 1
    assert min_cuts("abcd") == 3


def test_04_version_and_stdlib_only():
    assert dp_12.DP_12_VERSION == "dp-12.v1"
    assert dp_12.stdlib_only() is True
