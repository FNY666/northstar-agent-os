"""Tests for cc_29 (Powers-of-two denominations (greedy optimal))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_29
from cc_29 import powers_of_two, min_coins_pow2


def test_01_normal_case():
    assert powers_of_two(10) == [1, 2, 4, 8]
    assert min_coins_pow2(11) == 3
    assert min_coins_pow2(63) == 6


def test_02_edge_cases():
    assert powers_of_two(0) == []
    assert min_coins_pow2(0) == 0
    assert min_coins_pow2(1) == 1


def test_03_extra():
    try:
        min_coins_pow2(-1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # popcount property: greedy count equals number of 1-bits
    assert min_coins_pow2(13) == bin(13).count("1")


def test_04_version_and_stdlib_only():
    assert cc_29.CC_29_VERSION == "cc-29.v1"
    assert cc_29.stdlib_only() is True
