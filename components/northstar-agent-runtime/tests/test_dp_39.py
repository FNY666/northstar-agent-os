"""Tests for dp_39 (Interleaving string)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_39
from dp_39 import is_interleave


def test_01_normal_case():
    assert is_interleave("aabcc", "dbbca", "aadbbcbcac") is True
    assert is_interleave("aabcc", "dbbca", "aadbbbaccc") is False


def test_02_edge_cases():
    assert is_interleave("", "", "") is True
    assert is_interleave("a", "", "a") is True


def test_03_extra():
    assert is_interleave("ab", "cd", "abcd") is True
    assert is_interleave("ab", "cd", "acdb") is True
    assert is_interleave("a", "b", "ba") is True


def test_04_version_and_stdlib_only():
    assert dp_39.DP_39_VERSION == "dp-39.v1"
    assert dp_39.stdlib_only() is True
