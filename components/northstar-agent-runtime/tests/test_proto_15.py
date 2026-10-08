"""Tests for proto_15 (X.509 (mock))."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("proto_15")

def _cert(nb="2026-01-01", na="2027-01-01"):
    return "CERT\nserial: 7\nissuer: CN=CA\nsubject: CN=s\nnot_before: %s\nnot_after: %s\n" % (nb, na)


def test_fields():
    c = m.parse_cert(_cert())
    assert c["serial"] == "7" and c["issuer"] == "CN=CA"


def test_validity_window():
    import datetime as dt
    ok, _ = m.validate_cert(_cert(), today=dt.date(2026, 6, 1))
    assert ok is True
    ok, reason = m.validate_cert(_cert(), today=dt.date(2029, 1, 1))
    assert ok is False and "not valid" in reason


def test_missing_field():
    with pytest.raises(m.Proto15Error):
        m.parse_cert("CERT\nserial: 1\n")


def test_reversed_dates():
    with pytest.raises(m.Proto15Error):
        m.parse_cert(_cert("2027-01-01", "2026-01-01"))


def test_stdlib_only():
    assert m.stdlib_only() is True

