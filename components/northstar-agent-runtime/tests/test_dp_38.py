"""Tests for dp_38 (Delete operation for two strings)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_38
from dp_38 import min_delete


def test_01_normal_case():
    assert min_delete("sea", "eat") == 2
    assert min_delete("leetcode", "etco") == 4


def test_02_edge_cases():
    assert min_delete("", "") == 0
    assert min_delete("abc", "abc") == 0


def test_03_extra():
    assert min_delete("park", "spam") == 4
    assert min_delete("abcd", "efgh") == 8


def test_04_version_and_stdlib_only():
    assert dp_38.DP_38_VERSION == "dp-38.v1"
    assert dp_38.stdlib_only() is True
