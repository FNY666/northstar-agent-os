"""Tests for runtime_defense_15 (mtls)."""
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
d = _load("runtime_defense_15")
def _cfg():
    return d.build_config("keystore://agent/cert", ["Internal CA"], ["api.example.com", "*.internal.example"])
def test_allowed_host():
    assert _cfg().may_connect("api.example.com") is True
def test_wildcard_host():
    assert _cfg().may_connect("svc.internal.example") is True
def test_denied_host():
    assert _cfg().may_connect("evil.com") is False
def test_pem_refused():
    with pytest.raises(d.MtlsError):
        d.build_config("-----BEGIN CERTIFICATE-----\n...", ["ca"], ["h"])
def test_empty_ca_refused():
    with pytest.raises(d.MtlsError):
        d.build_config("ref", [], ["h"])
def test_nonstrict_refused():
    with pytest.raises(d.MtlsError):
        d.MtlsConfig(client_cert_ref="ref", server_ca_names=frozenset({"ca"}),
                     allowed_hosts=frozenset({"h"}), verify_mode="none")
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_15_VERSION == "runtime-defense-15.v1"
