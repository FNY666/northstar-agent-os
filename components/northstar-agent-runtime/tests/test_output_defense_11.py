"""Tests for output_defense_11."""
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
d = _load("output_defense_11")
def test_supported():
    ev = frozenset({"Paris is the capital of France."})
    v = d.detect_hallucination("Paris is the capital of France.", ev)
    assert v.flagged is False
def test_unverified():
    ev = frozenset({"Paris is the capital of France."})
    v = d.detect_hallucination("Studies show dragons definitely exist 99999.", ev)
    assert v.flagged is True and len(v.unverified_claims) == 1
def test_hedged_ok():
    ev = frozenset({"cats are pets."})
    v = d.detect_hallucination("Maybe it will rain.", ev)
    assert v.flagged is False
def test_fail_closed():
    with pytest.raises(d.HallucinationError):
        d.detect_hallucination("x", ["not", "a", "set"])  # type: ignore
def test_version():
    assert d.OUTPUT_DEFENSE_11_VERSION == "output-defense-11.v1"
    assert d.stdlib_only() is True
