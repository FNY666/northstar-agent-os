"""util_21 tests."""

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


m = _load("util_21")

def test_clamp():
    assert m.clamp(5, 0, 3) == 3
    assert m.clamp(-1, 0, 3) == 0
    assert m.clamp(2, 0, 3) == 2


def test_lerp_mean():
    assert m.lerp(0, 10, 0.5) == 5.0
    assert m.mean([1, 2, 3]) == 2.0


def test_percentile():
    assert m.percentile([1, 2, 3, 4], 50) == 2.5
    assert m.percentile([1, 2, 3, 4], 0) == 1
    assert m.percentile([1, 2, 3, 4], 100) == 4


def test_errors():
    import pytest
    with pytest.raises(m.MathError):
        m.mean([])
    with pytest.raises(m.MathError):
        m.percentile([1], 101)


def test_stdlib_only():
    assert m.stdlib_only() is True
