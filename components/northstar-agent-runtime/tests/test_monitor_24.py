"""Tests for monitor_24 (brand monitoring)."""
import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


bm = _load("monitor_24")


def test_levenshtein():
    assert bm.levenshtein("kitten", "sitting") == 3
    assert bm.levenshtein("abc", "abc") == 0
    assert bm.levenshtein("", "ab") == 2


def test_variant_lookalike():
    b = bm.BrandMonitor(["google.com"])
    assert b.check("google.org").verdict == "variant"
    v = b.check("googel.com")
    assert v.verdict == "lookalike" and v.score == 80


def test_suspicious_signals():
    b = bm.BrandMonitor(["acme.com"])
    v = b.check("xn--acm-9ta.com")
    assert "punycode" in v.reasons
    v = b.check("acme.tk")
    assert v.verdict == "variant"  # brand SLD on another TLD
    assert "suspicious tld .tk" in v.reasons
    v = b.check("totally-legit.tk")
    assert v.verdict == "suspicious"
    assert b.check("unrelated.example").verdict == "clean"


def test_fail_closed():
    b = bm.BrandMonitor(["a.com"])
    with pytest.raises(bm.BrandError):
        bm.BrandMonitor([])
    with pytest.raises(bm.BrandError):
        b.check("")
    with pytest.raises(bm.BrandError):
        b.check("nodot")


def test_stdlib_only():
    assert bm.stdlib_only() is True
