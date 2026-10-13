"""Tests for multi_attack_11 (foot-in-the-door)."""
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


m = _load("multi_attack_11")


def test_ratchet_detected():
    result = m.run_script(m.SCRIPTS[0], lambda p: False)
    assert result["ratchet"] >= 4.0
    assert result["stopped"] is True


def test_flat_requests_pass():
    flat = m.FootInDoorScript("f", "x", [
        m.FootInDoorTurn(1, "a", 0.2),
        m.FootInDoorTurn(2, "b", 0.25),
    ])
    result = m.run_script(flat, lambda p: False)
    assert result["stopped"] is False


def test_gate_block_stops():
    result = m.run_script(m.SCRIPTS[0], lambda p: "Purge" in p)
    assert result["blocked_turn"] == 5
    assert result["stopped"] is True


def test_gate_exception_fail_closed():
    def bad(p):
        raise RuntimeError("gate down")

    result = m.run_script(m.SCRIPTS[0], bad)
    assert result["blocked_turn"] == 1
    assert result["stopped"] is True


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.MULTI_ATTACK_11_VERSION == "multi-attack-11.v1"
    assert m.SCHEMA_PIN == "northstar.multi-attack-11.v1"
