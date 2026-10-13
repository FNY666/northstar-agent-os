"""Tests for runtime_defense_12 (proxy)."""
import importlib.util, sys
from pathlib import Path
import pytest
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
d = _load("runtime_defense_12")
def test_env():
    cfg = d.build_config("http://proxy.internal:3128", ["api.example.com"])
    assert cfg.env()["https_proxy"] == "http://proxy.internal:3128"
def test_connect_allowed():
    cfg = d.build_config("http://proxy.internal:3128", ["api.example.com", "*.cdn.net"])
    ok, _ = cfg.check_connect("api.example.com", 443)
    assert ok is True
    ok, _ = cfg.check_connect("x.cdn.net", 443)
    assert ok is True
def test_connect_denied_host():
    cfg = d.build_config("http://proxy.internal:3128", ["api.example.com"])
    ok, _ = cfg.check_connect("evil.com", 443)
    assert ok is False
def test_connect_denied_port():
    cfg = d.build_config("http://proxy.internal:3128", ["api.example.com"])
    ok, _ = cfg.check_connect("api.example.com", 22)
    assert ok is False
def test_bad_scheme_raises():
    with pytest.raises(d.ProxyError):
        d.build_config("ftp://proxy:21")
def test_no_port_raises():
    with pytest.raises(d.ProxyError):
        d.build_config("http://proxy-no-port")
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_12_VERSION == "runtime-defense-12.v1"
