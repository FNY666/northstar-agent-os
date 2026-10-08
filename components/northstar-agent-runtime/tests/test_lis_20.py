"""Tests for lis-20 (Longest string chain)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_20
from lis_20 import longest_string_chain


def test_01_normal_case():
    assert longest_string_chain(["a", "b", "ba", "bca", "bda", "bdca"]) == 4
    assert longest_string_chain(["xbc", "pcxbcf", "xb", "cxbc", "pcxbc"]) == 5
    assert longest_string_chain(["abcd", "dbqca"]) == 1


def test_02_edge_cases():
    assert longest_string_chain([]) == 0
    assert longest_string_chain(["a"]) == 1
    assert longest_string_chain(["a", "a", "ab"]) == 2


def test_03_validation():
    try:
        longest_string_chain(['a', 3])
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
    try:
        longest_string_chain('abc')
        raise AssertionError('expected ValueError')
    except ValueError:
        pass

def test_04_version_and_stdlib_only():
    assert lis_20.LIS_20_VERSION == "lis-20.v1"
    assert lis_20.stdlib_only() is True
