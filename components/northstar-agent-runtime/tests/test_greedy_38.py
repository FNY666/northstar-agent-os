"""Tests for greedy_38 (Huffman code lengths (simplified))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_38
from greedy_38 import huffman_code_lengths


def test_01_normal_case():
    d = huffman_code_lengths({"a": 5, "b": 9, "c": 12, "d": 13, "e": 16, "f": 45})
    assert d == {"a": 4, "b": 4, "c": 3, "d": 3, "e": 3, "f": 1}


def test_02_edge_cases():
    assert huffman_code_lengths({}) == {}
    assert huffman_code_lengths({"x": 7}) == {"x": 1}


def test_03_extra():
    assert huffman_code_lengths({"a": 1, "b": 1}) == {"a": 1, "b": 1}
    d = huffman_code_lengths({"a": 3, "b": 3, "c": 3})
    assert sorted(d.values()) == [1, 2, 2]


def test_04_version_and_stdlib_only():
    assert greedy_38.GREEDY_38_VERSION == "greedy-38.v1"
    assert greedy_38.stdlib_only() is True
