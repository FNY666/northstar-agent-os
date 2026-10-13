"""Runtime defense 24 tests."""

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


rd = _load("runtime_defense_24")


def test_match():
    mon = rd.IntegrityMonitor()
    mon.register("p", rd.sha256_text("abc"))
    ok, _ = mon.check("p", rd.sha256_text("abc"))
    assert ok is True


def test_drift():
    mon = rd.IntegrityMonitor()
    mon.register("p", rd.sha256_text("abc"))
    ok, reason = mon.check("p", rd.sha256_text("xyz"))
    assert ok is False
    assert "drift" in reason


def test_unregistered():
    mon = rd.IntegrityMonitor()
    ok, _ = mon.check("nope", rd.sha256_text("x"))
    assert ok is False


def test_drifted_list():
    mon = rd.IntegrityMonitor()
    mon.register("a", rd.sha256_text("1"))
    mon.register("b", rd.sha256_text("2"))
    bad = mon.drifted({"a": rd.sha256_text("1"), "b": rd.sha256_text("9")})
    assert bad == ["b"]


def test_rejects_bad_hash():
    mon = rd.IntegrityMonitor()
    with pytest.raises(rd.IntegrityError):
        mon.register("p", "md5:abc")


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_24_VERSION == "runtime-defense-24.v1"
