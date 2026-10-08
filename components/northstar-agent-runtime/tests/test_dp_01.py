"""Tests for dp_01 (Fibonacci numbers)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_01
from dp_01 import fib


def test_01_normal_case():
    assert fib(10) == 55
    assert fib(20) == 6765
    assert fib(2) == 1


def test_02_edge_cases():
    assert fib(0) == 0
    assert fib(1) == 1


def test_03_extra():
    try:
        fib(-5)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert fib(50) == 12586269025


def test_04_version_and_stdlib_only():
    assert dp_01.DP_01_VERSION == "dp-01.v1"
    assert dp_01.stdlib_only() is True
