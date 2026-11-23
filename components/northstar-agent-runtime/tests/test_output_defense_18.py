"""Tests for output_defense_18."""
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
d = _load("output_defense_18")
def test_passthrough():
    r = d.safe_complete("hello", lambda t: True)
    assert r.was_substituted is False and r.text == "hello"
def test_substitute():
    r = d.safe_complete("bad", lambda t: False)
    assert r.was_substituted is True and "blocked" in r.text
def test_checker_down():
    def boom(t):
        raise RuntimeError("x")
    r = d.safe_complete("hello", boom)
    assert r.was_substituted is True
def test_empty():
    r = d.safe_complete("   ", lambda t: True)
    assert r.was_substituted is True
def test_bad_fallback():
    with pytest.raises(d.SafeCompletionError):
        d.safe_complete("x", lambda t: True, fallback_key="nope")
def test_version():
    assert d.OUTPUT_DEFENSE_18_VERSION == "output-defense-18.v1"
    assert d.stdlib_only() is True
