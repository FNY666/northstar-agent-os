"""Tests for greedy_21 (Reorganize string)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_21
from greedy_21 import reorganize_string


def test_01_normal_case():
    r = reorganize_string("aab")
    assert len(r) == 3 and r[0] != r[1] and r[1] != r[2]


def test_02_edge_cases():
    assert reorganize_string("") == ""
    assert reorganize_string("a") == "a"


def test_03_extra():
    assert reorganize_string("aaab") == ""
    r = reorganize_string("vvvlo")
    assert len(r) == 5 and all(r[i] != r[i + 1] for i in range(4))


def test_04_version_and_stdlib_only():
    assert greedy_21.GREEDY_21_VERSION == "greedy-21.v1"
    assert greedy_21.stdlib_only() is True
