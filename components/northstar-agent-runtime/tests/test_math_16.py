"""Tests for math_16 (geometry)."""
import importlib.util
import math
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


m = _load("math_16")


def test_dist():
    assert m.dist((0, 0), (3, 4)) == pytest.approx(5.0)
    assert m.dist((1, 1, 1), (2, 2, 2)) == pytest.approx(math.sqrt(3))
    with pytest.raises(ValueError):
        m.dist((0, 0), (1, 2, 3))


def test_triangle_area():
    assert m.triangle_area((0, 0), (4, 0), (0, 3)) == pytest.approx(6.0)


def test_polygon_area():
    assert m.polygon_area([(0, 0), (4, 0), (4, 3), (0, 3)]) == pytest.approx(12.0)
    assert m.polygon_area([(0, 0), (1, 0), (0, 1)]) == pytest.approx(0.5)
    with pytest.raises(ValueError):
        m.polygon_area([(0, 0), (1, 1)])


def test_circle_rect():
    assert m.circle_area(1) == pytest.approx(math.pi)
    assert m.rect_area(3, 4) == 12
    with pytest.raises(ValueError):
        m.circle_area(-1)
