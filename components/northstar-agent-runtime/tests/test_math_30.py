"""Tests for math_30 (digit functions)."""
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


m = _load("math_30")


def test_digit_sum():
    assert m.digit_sum(12345) == 15
    assert m.digit_sum(0) == 0
    assert m.digit_sum(-999) == 27
    assert m.digit_sum(255, 16) == 30  # 0xFF -> F + F
    with pytest.raises(ValueError):
        m.digit_sum(10, 1)


def test_digital_root():
    assert m.digital_root(9875) == 2
    assert m.digital_root(9) == 9
    assert m.digital_root(0) == 0


def test_reverse():
    assert m.reverse_number(12345) == 54321
    assert m.reverse_number(-120) == -21
    assert m.reverse_number(1000) == 1


def test_palindrome():
    assert m.is_palindrome_number(12321) is True
    assert m.is_palindrome_number(12345) is False
    assert m.is_palindrome_number(7) is True
