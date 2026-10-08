"""Tests for dp_33 (Decode ways)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_33
from dp_33 import decode_ways


def test_01_normal_case():
    assert decode_ways("12") == 2
    assert decode_ways("226") == 3


def test_02_edge_cases():
    assert decode_ways("") == 0
    assert decode_ways("0") == 0
    assert decode_ways("06") == 0


def test_03_extra():
    assert decode_ways("11106") == 2
    assert decode_ways("2101") == 1
    assert decode_ways("99") == 1


def test_04_version_and_stdlib_only():
    assert dp_33.DP_33_VERSION == "dp-33.v1"
    assert dp_33.stdlib_only() is True
