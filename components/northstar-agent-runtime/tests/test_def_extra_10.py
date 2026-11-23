"""Tests for def_extra_10 (log integrity hash chain)."""
import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("def_extra_10")


def test_append_verify_ok():
    chain = m.LogChain()
    chain.append({"e": "a"}, now=1000.0)
    chain.append({"e": "b"}, now=1001.0)
    ok, detail = chain.verify()
    assert ok is True, detail


def test_tamper_detected():
    chain = m.LogChain()
    chain.append({"e": "a"}, now=1000.0)
    chain.append({"e": "b"}, now=1001.0)
    records = chain.records
    tampered = m.LogRecord(
        records[1].index, records[1].ts, records[1].prev,
        {"e": "forged"}, records[1].digest,
    )
    chain2 = m.LogChain()
    chain2._records = [records[0], tampered]
    ok, detail = chain2.verify()
    assert ok is False
    assert "digest mismatch" in detail


def test_empty_chain_ok():
    ok, _ = m.LogChain().verify()
    assert ok is True


def test_version_pin():
    assert m.DEF_EXTRA_10_VERSION == "def-extra-10.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-10.v1"
