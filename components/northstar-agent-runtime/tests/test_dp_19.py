"""Tests for dp_19 (Distinct subsequences)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_19
from dp_19 import distinct_subseq


def test_01_normal_case():
    assert distinct_subseq("rabbbit", "rabbit") == 3
    assert distinct_subseq("babgbag", "bag") == 5


def test_02_edge_cases():
    assert distinct_subseq("abc", "") == 1
    assert distinct_subseq("", "") == 1


def test_03_extra():
    assert distinct_subseq("daacaed", "aca") == 2
    assert distinct_subseq("abc", "abcd") == 0


def test_04_version_and_stdlib_only():
    assert dp_19.DP_19_VERSION == "dp-19.v1"
    assert dp_19.stdlib_only() is True
