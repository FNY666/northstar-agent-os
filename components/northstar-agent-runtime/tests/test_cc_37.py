"""Tests for cc_37 (Lexicographically smallest optimal change)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_37
from cc_37 import min_coins_lex_smallest


def test_01_normal_case():
    assert min_coins_lex_smallest(6, [1, 3, 4]) == (2, [3, 3])
    assert min_coins_lex_smallest(11, [1, 2, 5]) == (3, [1, 5, 5])


def test_02_edge_cases():
    assert min_coins_lex_smallest(0, [1]) == (0, [])
    assert min_coins_lex_smallest(3, [2]) == (-1, [])


def test_03_extra():
    try:
        min_coins_lex_smallest(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    count, used = min_coins_lex_smallest(8, [1, 4, 5])
    assert count == 2 and used == [4, 4]
    assert sum(used) == 8


def test_04_version_and_stdlib_only():
    assert cc_37.CC_37_VERSION == "cc-37.v1"
    assert cc_37.stdlib_only() is True
