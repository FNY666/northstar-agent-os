"""Tests for output_defense_12."""
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
d = _load("output_defense_12")
def _fc():
    kb = d.KnowledgeBase({"sky is blue": "textbook"})
    return d.FactualityChecker(kb)
def test_supported():
    v = _fc().check("Sky is blue")
    assert v.status == "supported"
def test_refuted():
    v = _fc().check("not sky is blue")
    assert v.status == "refuted"
def test_unknown():
    v = _fc().check("aliens landed")
    assert v.status == "unknown"
def test_fail_closed():
    with pytest.raises(d.FactualityError):
        _fc().check("")
    with pytest.raises(d.FactualityError):
        d.KnowledgeBase().add("", "s")
def test_version():
    assert d.OUTPUT_DEFENSE_12_VERSION == "output-defense-12.v1"
    assert d.stdlib_only() is True
