"""Tests for greedy_19 (Remove K digits)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_19
from greedy_19 import remove_k_digits


def test_01_normal_case():
    assert remove_k_digits("1432219", 3) == "1219"
    assert remove_k_digits("10200", 1) == "200"


def test_02_edge_cases():
    assert remove_k_digits("10", 2) == "0"
    assert remove_k_digits("9", 0) == "9"


def test_03_extra():
    assert remove_k_digits("112", 1) == "11"
    assert remove_k_digits("10001", 4) == "0"


def test_04_version_and_stdlib_only():
    assert greedy_19.GREEDY_19_VERSION == "greedy-19.v1"
    assert greedy_19.stdlib_only() is True
