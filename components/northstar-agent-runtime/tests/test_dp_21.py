"""Tests for dp_21 (Wildcard matching)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_21
from dp_21 import wildcard_match


def test_01_normal_case():
    assert wildcard_match("adceb", "*a*b") is True
    assert wildcard_match("aa", "*") is True


def test_02_edge_cases():
    assert wildcard_match("", "*") is True
    assert wildcard_match("", "?") is False


def test_03_extra():
    assert wildcard_match("abcde", "a*e") is True
    assert wildcard_match("abcde", "a?c*e") is True
    assert wildcard_match("abcde", "a*d") is False


def test_04_version_and_stdlib_only():
    assert dp_21.DP_21_VERSION == "dp-21.v1"
    assert dp_21.stdlib_only() is True
