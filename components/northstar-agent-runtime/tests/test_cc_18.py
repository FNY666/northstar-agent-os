"""Tests for cc_18 (Minimum coins (prime denominations only))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_18
from cc_18 import min_coins_prime_denoms


def test_01_normal_case():
    assert min_coins_prime_denoms(10, [1, 2, 5, 10]) == 2
    assert min_coins_prime_denoms(7, [2, 3, 7]) == 1


def test_02_edge_cases():
    assert min_coins_prime_denoms(0, [2, 3]) == 0
    assert min_coins_prime_denoms(11, [1, 2, 5, 10]) == 4
    assert min_coins_prime_denoms(1, [2, 3]) == -1


def test_03_extra():
    try:
        min_coins_prime_denoms(-1, [2])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins_prime_denoms(4, [4, 6, 8]) == -1


def test_04_version_and_stdlib_only():
    assert cc_18.CC_18_VERSION == "cc-18.v1"
    assert cc_18.stdlib_only() is True
