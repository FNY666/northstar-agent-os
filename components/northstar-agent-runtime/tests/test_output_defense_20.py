"""Tests for output_defense_20."""
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
d = _load("output_defense_20")
SRC = "word " * 1000
def test_ok():
    v = d.guard_summary("a reasonable summary of the document content here " * 5, SRC)
    assert v.ok is True
def test_truncate():
    v = d.guard_summary("x " * 2000, SRC, max_chars=50, mode="truncate")
    assert v.ok is True and len(v.text) <= 54
def test_reject_long():
    v = d.guard_summary("x " * 2000, SRC, max_chars=50, mode="reject")
    assert v.ok is False
def test_verbatim_dump():
    small = "word " * 100  # 500 chars, under max_chars
    v = d.guard_summary(small, small)
    assert v.ok is False and "verbatim" in v.reason
def test_too_short():
    v = d.guard_summary("tiny", SRC)
    assert v.ok is False
def test_fail_closed():
    with pytest.raises(d.SummaryGuardError):
        d.guard_summary(None, SRC)  # type: ignore
def test_version():
    assert d.OUTPUT_DEFENSE_20_VERSION == "output-defense-20.v1"
    assert d.stdlib_only() is True
