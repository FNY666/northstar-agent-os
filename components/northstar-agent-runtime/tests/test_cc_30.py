"""Tests for cc_30 (Powers-of-three denominations)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_30
from cc_30 import powers_of_three, min_coins_pow3


def test_01_normal_case():
    assert powers_of_three(10) == [1, 3, 9]
    assert min_coins_pow3(11) == 3
    assert min_coins_pow3(18) == 2


def test_02_edge_cases():
    assert powers_of_three(0) == []
    assert min_coins_pow3(0) == 0
    assert min_coins_pow3(2) == 2


def test_03_extra():
    try:
        min_coins_pow3(-4)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins_pow3(27) == 1


def test_04_version_and_stdlib_only():
    assert cc_30.CC_30_VERSION == "cc-30.v1"
    assert cc_30.stdlib_only() is True
