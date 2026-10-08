"""util_26 tests."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("util_26")

import enum


class _Color(enum.Enum):
    RED = 1
    BLUE = 2


def test_from_value():
    assert m.from_value(_Color, 1) is _Color.RED
    assert m.from_value(_Color, 99, default=_Color.BLUE) is _Color.BLUE


def test_from_value_raises():
    import pytest
    with pytest.raises(m.EnumError):
        m.from_value(_Color, 99)


def test_names_values_dict():
    assert m.names(_Color) == ["RED", "BLUE"]
    assert m.values(_Color) == [1, 2]
    assert m.to_dict(_Color) == {"RED": 1, "BLUE": 2}


def test_stdlib_only():
    assert m.stdlib_only() is True
