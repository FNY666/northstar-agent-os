"""Tests for output_defense_13."""
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
d = _load("output_defense_13")
REFS = ["[1] Smith (2020). X.", "[2] Doe (2021). Y."]
def test_verified():
    v = d.verify_citations("See [1] and [2].", REFS)
    assert v.verified is True
def test_fabricated():
    v = d.verify_citations("See [1] and [9].", REFS)
    assert v.verified is False and "[9]" in v.unmatched
def test_none():
    v = d.verify_citations("Plain text.", REFS)
    assert v.verified is True and v.citations_found == []
def test_fail_closed():
    with pytest.raises(d.CitationError):
        d.verify_citations("x [1]", {})  # type: ignore
def test_version():
    assert d.OUTPUT_DEFENSE_13_VERSION == "output-defense-13.v1"
    assert d.stdlib_only() is True
