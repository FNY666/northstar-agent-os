"""Tests for algo_49: palindrome partitioning (minimum cuts)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import algo_49 as a49
from algo_49 import min_cuts


def test_version_pin_and_stdlib_only():
    assert a49.ALGO_49_VERSION == "algo-49.v1"
    assert a49.stdlib_only() is True


def test_min_cuts_classic():
    assert min_cuts("aab") == 1  # aa | b


def test_min_cuts_edge_cases():
    assert min_cuts("") == 0
    assert min_cuts("a") == 0
    assert min_cuts("ab") == 1
    assert min_cuts("aaaa") == 0


def test_min_cuts_palindromes():
    assert min_cuts("aba") == 0
    assert min_cuts("abcbm") == 2  # a | bcb | m
    assert min_cuts("abcde") == 4  # every char alone
    assert min_cuts("noonabbad") == 2  # noon | abba | d
