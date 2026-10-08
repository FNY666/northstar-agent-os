"""Tests for dp_18 (Longest palindromic substring)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_18
from dp_18 import longest_pal_substr


def test_01_normal_case():
    assert longest_pal_substr("babad") in ("bab", "aba")
    assert longest_pal_substr("cbbd") == "bb"


def test_02_edge_cases():
    assert longest_pal_substr("") == ""
    assert longest_pal_substr("a") == "a"


def test_03_extra():
    assert longest_pal_substr("abccba") == "abccba"
    assert longest_pal_substr("aaaa") == "aaaa"


def test_04_version_and_stdlib_only():
    assert dp_18.DP_18_VERSION == "dp-18.v1"
    assert dp_18.stdlib_only() is True
