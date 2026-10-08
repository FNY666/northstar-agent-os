"""Tests for output_defense_14."""
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
d = _load("output_defense_14")
def _t():
    t = d.AttributionTracker()
    t.register(d.Source("s1", "tool"))
    return t
def test_full_coverage():
    t = _t()
    t.attribute(0, 100, "s1")
    assert t.coverage(100) == 1.0
    assert t.unattributed_gaps(100) == []
def test_gaps():
    t = _t()
    t.attribute(0, 10, "s1")
    assert t.unattributed_gaps(100, min_gap=20) == [(10, 100)]
def test_unknown_source():
    with pytest.raises(d.AttributionError):
        _t().attribute(0, 10, "ghost")
def test_bad_span():
    with pytest.raises(d.AttributionError):
        _t().attribute(10, 5, "s1")
def test_version():
    assert d.OUTPUT_DEFENSE_14_VERSION == "output-defense-14.v1"
    assert d.stdlib_only() is True
