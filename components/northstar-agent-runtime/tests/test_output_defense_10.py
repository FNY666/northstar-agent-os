"""Tests for output_defense_10."""
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
d = _load("output_defense_10")
def test_clean():
    v = d.detect_bias("The report is due Friday.")
    assert v.flagged is False and v.findings == []
def test_flagged():
    v = d.detect_bias("All men are naturally better at this.")
    assert v.flagged is True and len(v.findings) >= 1
def test_fail_closed():
    with pytest.raises(d.BiasError):
        d.detect_bias(42)  # type: ignore
def test_version():
    assert d.OUTPUT_DEFENSE_10_VERSION == "output-defense-10.v1"
    assert d.stdlib_only() is True
