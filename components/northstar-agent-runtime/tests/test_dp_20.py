"""Tests for dp_20 (Regular expression matching)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_20
from dp_20 import is_match


def test_01_normal_case():
    assert is_match("aa", "a*") is True
    assert is_match("aab", "c*a*b") is True


def test_02_edge_cases():
    assert is_match("", "") is True
    assert is_match("", "a*") is True
    assert is_match("a", "") is False


def test_03_extra():
    assert is_match("ab", ".*c") is False
    assert is_match("aaa", "a*a") is True
    assert is_match("aaa", "ab*a*c*a") is True


def test_04_version_and_stdlib_only():
    assert dp_20.DP_20_VERSION == "dp-20.v1"
    assert dp_20.stdlib_only() is True
