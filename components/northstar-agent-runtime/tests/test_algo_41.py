"""Tests for algo_41: Fibonacci (iterative + memoised)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import algo_41 as a41
from algo_41 import fib, fib_memo


def test_version_pin_and_stdlib_only():
    assert a41.ALGO_41_VERSION == "algo-41.v1"
    assert a41.stdlib_only() is True


def test_fib_classic_values():
    assert fib(0) == 0
    assert fib(1) == 1
    assert fib(2) == 1
    assert fib(10) == 55
    assert fib(20) == 6765
    assert fib(30) == 832040


def test_fib_memo_agrees_with_iterative():
    assert fib_memo(0) == 0
    assert fib_memo(1) == 1
    assert all(fib_memo(i) == fib(i) for i in range(50))


def test_negative_n_raises():
    with pytest.raises(ValueError):
        fib(-1)
    with pytest.raises(ValueError):
        fib_memo(-7)
