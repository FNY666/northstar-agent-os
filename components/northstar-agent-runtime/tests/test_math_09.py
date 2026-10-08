"""Tests for math_09 (eigenvalues 2x2)."""
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


m = _load("math_09")


def test_diagonal():
    assert m.eigenvalues_2x2(2, 0, 0, 3) == (3.0, 2.0)


def test_rotation_complex():
    l1, l2 = m.eigenvalues_2x2(0, -1, 1, 0)
    assert abs(l1 - 1j) < 1e-9
    assert abs(l2 + 1j) < 1e-9


def test_trace_det_relations():
    l1, l2 = m.eigenvalues_2x2(4, 1, 2, 3)
    assert abs((l1 + l2) - 7.0) < 1e-9
    assert abs((l1 * l2) - 10.0) < 1e-9


def test_repeated_eigenvalue():
    l1, l2 = m.eigenvalues_2x2(2, 1, 0, 2)
    assert abs(l1 - 2.0) < 1e-9 and abs(l2 - 2.0) < 1e-9
