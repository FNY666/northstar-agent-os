"""Tests for dp_37 (Shortest common supersequence (length))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_37
from dp_37 import scs_length


def test_01_normal_case():
    assert scs_length("abac", "cab") == 5
    assert scs_length("geek", "eke") == 5


def test_02_edge_cases():
    assert scs_length("", "") == 0
    assert scs_length("abc", "abc") == 3


def test_03_extra():
    assert scs_length("AGGTAB", "GXTXAYB") == 9
    assert scs_length("a", "b") == 2


def test_04_version_and_stdlib_only():
    assert dp_37.DP_37_VERSION == "dp-37.v1"
    assert dp_37.stdlib_only() is True
