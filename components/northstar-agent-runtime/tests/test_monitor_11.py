"""Tests for monitor_11 (IOC matching)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


im = _load("monitor_11")

INDS = [
    {"type": "ip", "value": "1.2.3.4", "confidence": 90},
    {"type": "cidr", "value": "10.0.0.0/8", "confidence": 70},
    {"type": "domain", "value": "evil.example", "confidence": 80},
    {"type": "hash", "value": "ab" * 32, "confidence": 95},
]


def test_exact_and_cidr():
    m = im.IocMatcher(INDS)
    assert m.match("ip", "1.2.3.4")[0].match_kind == "exact"
    assert m.match("ip", "10.9.9.9")[0].match_kind == "cidr"
    assert m.match("ip", "8.8.8.8") == []


def test_domain_suffix_and_url():
    m = im.IocMatcher(INDS)
    assert m.match("domain", "sub.evil.example")[0].match_kind == "suffix"
    assert m.match("url", "https://evil.example/x")[0].match_kind == "url_host"


def test_hash_exact():
    m = im.IocMatcher(INDS)
    assert len(m.match("hash", "ab" * 32)) == 1
    assert m.match("hash", "cd" * 32) == []


def test_bad_inputs():
    import pytest

    m = im.IocMatcher(INDS)
    with pytest.raises(im.IocMatchError):
        m.match("bogus", "x")
    with pytest.raises(im.IocMatchError):
        m.match("ip", "not-an-ip")
    with pytest.raises(im.IocMatchError):
        im.IocMatcher([{"type": "bogus", "value": "x"}])


def test_stdlib_only():
    assert im.stdlib_only() is True
