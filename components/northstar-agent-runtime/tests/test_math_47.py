"""Tests for math_47 (base conversion)."""
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


m = _load("math_47")


def test_to_base():
    assert m.to_base(255, 16) == "FF"
    assert m.to_base(-10, 2) == "-1010"
    assert m.to_base(0, 8) == "0"
    assert m.to_base(35, 36) == "Z"


def test_from_base():
    assert m.from_base("FF", 16) == 255
    assert m.from_base("-1010", 2) == -10
    assert m.from_base("z", 36) == 35
    with pytest.raises(ValueError):
        m.from_base("2", 2)


def test_round_trip():
    for n in (0, 1, 42, 123456, -999):
        for base in (2, 8, 10, 16, 36):
            assert m.from_base(m.to_base(n, base), base) == n


def test_roman():
    assert m.int_to_roman(2026) == "MMXXVI"
    assert m.int_to_roman(4) == "IV"
    assert m.roman_to_int("MMXXVI") == 2026
    assert m.roman_to_int("iv") == 4
    with pytest.raises(ValueError):
        m.int_to_roman(4000)
