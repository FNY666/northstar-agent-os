"""Tests for math_10 (FFT)."""
import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("math_10")


def test_fft_delta():
    X = m.fft([1, 0, 0, 0])
    assert all(abs(v - 1) < 1e-9 for v in X)


def test_fft_matches_dft():
    x = [1, 2, 3, 4, 5, 6, 7, 8]
    assert all(abs(a - b) < 1e-9 for a, b in zip(m.fft(x), m.dft(x)))


def test_round_trip():
    x = [1.0, 2.0, 3.0, 4.0, 5.0]
    back = m.idft(m.dft(x))
    assert all(abs(a - b) < 1e-9 for a, b in zip(back, x))


def test_bad_length():
    with pytest.raises(ValueError):
        m.fft([1, 2, 3])
    assert m.is_pow2(8) is True
    assert m.is_pow2(7) is False
