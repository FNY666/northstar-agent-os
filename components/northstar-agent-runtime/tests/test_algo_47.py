"""Tests for algo_47: matrix chain multiplication order."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import algo_47 as a47
from algo_47 import matrix_chain


def test_version_pin_and_stdlib_only():
    assert a47.ALGO_47_VERSION == "algo-47.v1"
    assert a47.stdlib_only() is True


def test_matrix_chain_classic():
    # (1x2)(2x3)(3x4): (A1*A2)*A3 costs 1*2*3 + 1*3*4 = 18
    assert matrix_chain([1, 2, 3, 4]) == 18


def test_matrix_chain_edge_cases():
    assert matrix_chain([3, 5]) == 0  # single matrix: no multiplication
    assert matrix_chain([2, 3, 4]) == 24  # only one parenthesization
    assert matrix_chain([10, 30, 5, 60]) == 4500
    assert matrix_chain([40, 20, 30, 10, 30]) == 26000


def test_matrix_chain_rejects_bad_dims():
    with pytest.raises(ValueError):
        matrix_chain([5])
    with pytest.raises(ValueError):
        matrix_chain([])
    with pytest.raises(ValueError):
        matrix_chain([2, -3, 4])
