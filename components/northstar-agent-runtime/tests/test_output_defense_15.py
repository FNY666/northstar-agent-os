"""Tests for output_defense_15."""
import importlib.util, sys
from pathlib import Path
import pytest
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s)
    sys.modules[n] = m
    s.loader.exec_module(m)
    return m
d = _load("output_defense_15")
def test_control_points():
    assert d.calibrate(0.9).calibrated == 0.88
    assert d.calibrate(0.5).calibrated == 0.45
def test_interpolation():
    r = d.calibrate(0.8)
    assert 0.72 < r.calibrated < 0.88
def test_overconfident():
    assert d.is_overconfident(0.75, margin=0.01) is True
    assert d.is_overconfident(0.9, margin=0.1) is False
def test_fail_closed():
    with pytest.raises(d.CalibrationError):
        d.calibrate(1.2)
    with pytest.raises(d.CalibrationError):
        d.calibrate("x")  # type: ignore
def test_version():
    assert d.OUTPUT_DEFENSE_15_VERSION == "output-defense-15.v1"
    assert d.stdlib_only() is True
