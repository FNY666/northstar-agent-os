"""Tests for math_12 (probability)."""
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


m = _load("math_12")


def test_uniform():
    assert m.p_uniform(1, 6) == pytest.approx(1 / 6)
    assert m.p_uniform(0, 10) == 0.0
    with pytest.raises(ValueError):
        m.p_uniform(3, 0)


def test_complement_union():
    assert m.p_complement(0.3) == pytest.approx(0.7)
    assert m.p_union_independent(0.5, 0.5) == pytest.approx(0.75)


def test_conditional():
    assert m.p_conditional(0.2, 0.5) == pytest.approx(0.4)
    with pytest.raises(ValueError):
        m.p_conditional(0.6, 0.5)
    with pytest.raises(ValueError):
        m.p_conditional(0.1, 0.0)


def test_bayes():
    post = m.bayes(0.99, 0.01, 0.99 * 0.01 + 0.01 * 0.99)
    assert post == pytest.approx(0.5)
    with pytest.raises(ValueError):
        m.bayes(0.5, 0.5, 0.0)
