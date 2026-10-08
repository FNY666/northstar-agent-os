"""Tests for dp_09 (Longest common subsequence (length))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_09
from dp_09 import lcs


def test_01_normal_case():
    assert lcs("abcde", "ace") == 3
    assert lcs("ezupkr", "ubmrapg") == 2


def test_02_edge_cases():
    assert lcs("", "") == 0
    assert lcs("abc", "abc") == 3


def test_03_extra():
    assert lcs("AGGTAB", "GXTXAYB") == 4
    assert lcs("aaaa", "aa") == 2


def test_04_version_and_stdlib_only():
    assert dp_09.DP_09_VERSION == "dp-09.v1"
    assert dp_09.stdlib_only() is True
