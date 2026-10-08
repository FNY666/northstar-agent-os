"""Tests for cc_31 (Fibonacci denominations counting)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_31
from cc_31 import fibonacci_denominations, count_ways_fib


def test_01_normal_case():
    assert fibonacci_denominations(10) == [1, 2, 3, 5, 8]
    assert count_ways_fib(5) == 6


def test_02_edge_cases():
    assert fibonacci_denominations(0) == []
    assert count_ways_fib(0) == 1
    assert count_ways_fib(1) == 1


def test_03_extra():
    try:
        count_ways_fib(-1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert count_ways_fib(8) == 14


def test_04_version_and_stdlib_only():
    assert cc_31.CC_31_VERSION == "cc-31.v1"
    assert cc_31.stdlib_only() is True
