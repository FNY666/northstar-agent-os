"""Tests for dp_36 (Longest common substring)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_36
from dp_36 import lc_substr


def test_01_normal_case():
    assert lc_substr("abcde", "abfce") == 2
    assert lc_substr("abcdxyz", "xyzabcd") == 4


def test_02_edge_cases():
    assert lc_substr("", "") == 0
    assert lc_substr("abc", "abc") == 3


def test_03_extra():
    assert lc_substr("zxabcdezy", "yzabcdezx") == 6
    assert lc_substr("a", "a") == 1


def test_04_version_and_stdlib_only():
    assert dp_36.DP_36_VERSION == "dp-36.v1"
    assert dp_36.stdlib_only() is True
