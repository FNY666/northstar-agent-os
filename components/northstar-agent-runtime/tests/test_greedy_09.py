"""Tests for greedy_09 (Partition labels)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_09
from greedy_09 import partition_labels


def test_01_normal_case():
    assert partition_labels("ababcbacadefegdehijhklij") == [9, 7, 8]


def test_02_edge_cases():
    assert partition_labels("") == []
    assert partition_labels("a") == [1]


def test_03_extra():
    assert partition_labels("eccbbbbdec") == [10]
    assert partition_labels("abc") == [1, 1, 1]


def test_04_version_and_stdlib_only():
    assert greedy_09.GREEDY_09_VERSION == "greedy-09.v1"
    assert greedy_09.stdlib_only() is True
