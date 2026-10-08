"""Tests for dp_14 (Matrix chain multiplication)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_14
from dp_14 import matrix_chain


def test_01_normal_case():
    assert matrix_chain([1, 2, 3, 4]) == 18
    assert matrix_chain([40, 20, 30, 10, 30]) == 26000


def test_02_edge_cases():
    assert matrix_chain([10, 20]) == 0
    assert matrix_chain([5]) == 0


def test_03_extra():
    assert matrix_chain([10, 20, 30]) == 6000
    assert matrix_chain([2, 3, 4, 5]) == 64


def test_04_version_and_stdlib_only():
    assert dp_14.DP_14_VERSION == "dp-14.v1"
    assert dp_14.stdlib_only() is True
