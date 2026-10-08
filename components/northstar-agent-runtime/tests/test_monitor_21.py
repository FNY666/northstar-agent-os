"""Tests for monitor_21 (canary files)."""
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


cf = _load("monitor_21")


def test_create_and_check(tmp_path):
    c = cf.CanaryFiles(tmp_path)
    p = c.create("trip1")
    assert p.is_file()
    assert c.check("trip1") == "ok"
    assert c.check_all() == {"trip1": "ok"}


def test_modified_and_missing(tmp_path):
    c = cf.CanaryFiles(tmp_path)
    p = c.create("trip2")
    p.write_bytes(b"tampered")
    assert c.check("trip2") == "modified"
    p.unlink()
    assert c.check("trip2") == "missing"
    c.remove("trip2")
    assert c.check_all() == {}


def test_tokens_unique(tmp_path):
    c = cf.CanaryFiles(tmp_path)
    p1 = c.create("a")
    p2 = c.create("b")
    assert p1.read_bytes() != p2.read_bytes()


def test_fail_closed(tmp_path):
    c = cf.CanaryFiles(tmp_path)
    with pytest.raises(cf.CanaryError):
        c.create("../evil")
    with pytest.raises(cf.CanaryError):
        c.create("a/b")
    with pytest.raises(cf.CanaryError):
        c.create(".hidden")
    with pytest.raises(cf.CanaryError):
        c.check("ghost")
    c.create("dup")
    with pytest.raises(cf.CanaryError):
        c.create("dup")


def test_stdlib_only():
    assert cf.stdlib_only() is True
