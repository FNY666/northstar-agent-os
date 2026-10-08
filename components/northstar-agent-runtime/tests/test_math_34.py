"""Tests for math_34 (golden section)."""
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


m = _load("math_34")


def test_shifted():
    assert m.golden_minimize(lambda t: (t - 2) ** 2, 0.0, 5.0) == pytest.approx(2.0, abs=1e-6)


def test_symmetric():
    assert m.golden_minimize(lambda t: t**2, -3.0, 7.0) == pytest.approx(0.0, abs=1e-6)


def test_narrow():
    f = lambda t: (t - 1.5) ** 2 + 3  # noqa: E731
    assert m.golden_minimize(f, 0.0, 3.0) == pytest.approx(1.5, abs=1e-6)


def test_bad_interval():
    with pytest.raises(ValueError):
        m.golden_minimize(lambda t: t, 2.0, 1.0)
