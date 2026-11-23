"""Tests for multi_attack_19 (leading question chains)."""
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


m = _load("multi_attack_19")


def test_narrowing_detected():
    r = m.run_script(m.SCRIPTS[0], lambda p: False)
    assert r["narrowing"] >= 0.9
    assert r["narrowed"] is True
    assert r["stopped"] is True
    r2 = m.run_script(m.SCRIPTS[1], lambda p: False)
    assert r2["stopped"] is True


def test_open_questions_pass():
    r = m.run_script(m.SCRIPTS[2], lambda p: False)
    assert r["stopped"] is False


def test_gate_block_mid_chain():
    r = m.run_script(m.SCRIPTS[1], lambda p: "deploy key" in p)
    assert r["blocked_turn"] == 3
    assert r["stopped"] is True


def test_gate_exception_fail_closed():
    def bad(p):
        raise RuntimeError("gate down")

    r = m.run_script(m.SCRIPTS[0], bad)
    assert r["blocked_turn"] == 1
    assert r["stopped"] is True


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.MULTI_ATTACK_19_VERSION == "multi-attack-19.v1"
    assert m.SCHEMA_PIN == "northstar.multi-attack-19.v1"
