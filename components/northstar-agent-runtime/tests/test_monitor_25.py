"""Tests for monitor_25 (phishing URL check)."""
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


ph = _load("monitor_25")


def _pd():
    return ph.PhishDetector(brands=frozenset({"paypal", "google"}))


def test_benign():
    v = _pd().check("https://www.google.com/search")
    assert v.verdict == "benign" and v.score == 0


def test_ip_and_userinfo():
    v = _pd().check("http://10.0.0.1/login")
    assert "ip-literal host" in v.reasons
    assert v.verdict == "phishing"
    v = _pd().check("https://user@evil.com/")
    assert "userinfo/@ in authority" in v.reasons


def test_lookalike_and_bait():
    v = _pd().check("https://paypa1.com/")
    assert any("lookalike of brand paypal" in r for r in v.reasons)
    v = _pd().check("https://paypal.com.evil.tk/")
    assert any("subdomain bait" in r for r in v.reasons)


def test_shortener_and_tld():
    v = _pd().check("https://bit.ly/x1")
    assert "url shortener" in v.reasons
    v = _pd().check("https://legit.tk/")
    assert any("suspicious tld" in r for r in v.reasons)


def test_fail_closed():
    p = _pd()
    with pytest.raises(ph.PhishError):
        p.check("")
    with pytest.raises(ph.PhishError):
        p.check("ftp://x.com/")
    with pytest.raises(ph.PhishError):
        p.check("notaurl")


def test_stdlib_only():
    assert ph.stdlib_only() is True
