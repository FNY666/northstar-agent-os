"""Tests for monitor_08 (SIEM/CEF)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


cef = _load("monitor_08")


def test_render():
    e = cef.CefEvent(signature_id="s1", name="test", severity="7", extensions={"k": "v"})
    out = e.render()
    assert out.startswith("CEF:0|")
    assert "k=v" in out


def test_escaping():
    e = cef.CefEvent(signature_id="s", name="a|b", severity="1", extensions={"k": "x=y"})
    out = e.render()
    assert "a\\|b" in out and "x\\=y" in out


def test_gate_denial():
    out = cef.gate_denial_cef("exec", "authorize", "blocked")
    assert "act=deny" in out and "tool=exec" in out


def test_bad_severity():
    import pytest

    with pytest.raises(cef.CefError):
        cef.CefEvent(signature_id="s", name="n", severity="99")


def test_stdlib_only():
    assert cef.stdlib_only() is True
