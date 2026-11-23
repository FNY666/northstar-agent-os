"""Tests for output_defense_17."""
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
d = _load("output_defense_17")
def test_refusal():
    v = d.detect_refusal("I can't help with that request.")
    assert v.is_refusal is True and v.is_partial is False
def test_not_refusal():
    v = d.detect_refusal("The capital is Paris.")
    assert v.is_refusal is False
def test_partial():
    v = d.detect_refusal("I'm unable to do that. " + "Here is a long unrelated discussion. " * 12)
    assert v.is_refusal is True and v.is_partial is True
def test_fail_closed():
    with pytest.raises(d.RefusalError):
        d.detect_refusal(None)  # type: ignore
def test_version():
    assert d.OUTPUT_DEFENSE_17_VERSION == "output-defense-17.v1"
    assert d.stdlib_only() is True
