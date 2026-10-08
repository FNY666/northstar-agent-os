"""Tests for dp_17 (Longest palindromic subsequence)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_17
from dp_17 import lps


def test_01_normal_case():
    assert lps("bbbab") == 4
    assert lps("cbbd") == 2


def test_02_edge_cases():
    assert lps("") == 0
    assert lps("a") == 1


def test_03_extra():
    assert lps("racecar") == 7
    assert lps("abcda") == 3


def test_04_version_and_stdlib_only():
    assert dp_17.DP_17_VERSION == "dp-17.v1"
    assert dp_17.stdlib_only() is True
