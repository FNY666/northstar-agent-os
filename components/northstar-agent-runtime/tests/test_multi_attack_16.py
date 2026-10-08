"""Tests for multi_attack_16 (memory manipulation)."""
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


m = _load("multi_attack_16")

RECORDS = {"budget": "100", "admin_approved": "false"}


def _lookup(key):
    return RECORDS.get(key)


def test_implants_stopped_control_passes():
    summary = m.run_all(m.CLAIMS, _lookup, lambda p: False)
    by_id = {r["claim_id"]: r for r in summary["results"]}
    assert by_id["mem-001"]["stopped"] is True
    assert by_id["mem-002"]["stopped"] is True
    assert by_id["mem-003"]["stopped"] is False  # control


def test_unknown_key_fail_closed():
    claim = m.MemoryClaim("x", "ghost", "v", "p", "g")
    r = m.verify_memory(claim, _lookup)
    assert r["stopped"] is True
    assert r["reason"] == "no verifiable record"


def test_lookup_exception_fail_closed():
    def bad(key):
        raise RuntimeError("store down")

    r = m.verify_memory(m.CLAIMS[0], bad)
    assert r["stopped"] is True


def test_gate_block():
    summary = m.run_all(m.CLAIMS, _lookup, lambda p: True)
    assert summary["stopped"] == summary["total"]


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.MULTI_ATTACK_16_VERSION == "multi-attack-16.v1"
    assert m.SCHEMA_PIN == "northstar.multi-attack-16.v1"
