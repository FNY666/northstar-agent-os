"""Tests for output_defense_19."""
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
d = _load("output_defense_19")
def test_patterns():
    r = d.redact_patterns("mail bob@x.com or 555-123-4567")
    assert r.redacted_count == 2 and "bob@x.com" not in r.text
    assert "mail" in r.text  # rest preserved
def test_spans():
    assert d.redact_spans("hello world", [(6, 11)]) == "hello [REDACTED]"
def test_clean():
    r = d.redact_patterns("nothing here")
    assert r.redacted_count == 0
def test_fail_closed():
    with pytest.raises(d.RedactionError):
        d.redact_spans("abc", [(5, 1)])
    with pytest.raises(d.RedactionError):
        d.redact_patterns(123)  # type: ignore
def test_version():
    assert d.OUTPUT_DEFENSE_19_VERSION == "output-defense-19.v1"
    assert d.stdlib_only() is True
