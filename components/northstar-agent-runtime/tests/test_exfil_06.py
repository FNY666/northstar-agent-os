"""Timing channel detection tests."""

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


m = _load("exfil_06")

def test_benign():
    import random
    random.seed(7)
    benign = [abs(random.gauss(0.1, 0.02)) for _ in range(30)]
    ok, _ = m.detect_timing_channel(benign)
    assert ok is False


def test_bimodal():
    covert = [0.05] * 15 + [0.5] * 15
    ok, reason = m.detect_timing_channel(covert)
    assert ok is True
    assert "bimodal" in reason


def test_too_few():
    ok, _ = m.detect_timing_channel([0.1, 0.2])
    assert ok is False


def test_negative_raises():
    import pytest
    with pytest.raises(m.Exfil06Error):
        m.detect_timing_channel([0.1] * 19 + [-1.0])


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_06_VERSION == "exfil-06.v1"
