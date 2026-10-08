"""Tests for dp_13 (Word break)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_13
from dp_13 import word_break


def test_01_normal_case():
    assert word_break("leetcode", ["leet", "code"]) is True
    assert word_break("applepenapple", ["apple", "pen"]) is True


def test_02_edge_cases():
    assert word_break("", ["a"]) is True
    assert word_break("a", []) is False


def test_03_extra():
    assert word_break("aaaaaaa", ["aaaa", "aaa"]) is True
    assert word_break("abcd", ["a", "abc", "b", "cd"]) is True


def test_04_version_and_stdlib_only():
    assert dp_13.DP_13_VERSION == "dp-13.v1"
    assert dp_13.stdlib_only() is True
