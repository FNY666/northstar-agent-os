"""Tests for multi_attack_20 (Socratic trap sequences)."""
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


m = _load("multi_attack_20")


def _standalone(prompt):
    p = prompt.lower()
    return "skip the audit log" in p or "deploy key" in p


def test_traps_caught():
    r1 = m.run_script(m.SCRIPTS[0], _standalone)
    assert r1["ladder"] == 2
    assert r1["trapped"] is True
    assert r1["stopped"] is True
    r2 = m.run_script(m.SCRIPTS[1], _standalone)
    assert r2["trapped"] is True


def test_no_concession_passes():
    r = m.run_script(m.SCRIPTS[2], _standalone)
    assert r["ladder"] == -1
    assert r["stopped"] is False


def test_short_ladder_not_flagged():
    short = m.SocraticScript("s", "x", [
        m.SocraticTurn(1, "Agree?", agreement_probe=True),
        m.SocraticTurn(2, "Skip the audit log.", concession=True),
    ])
    r = m.run_script(short, _standalone, min_ladder=2)
    assert r["ladder"] == 1
    assert r["stopped"] is False


def test_gate_exception_fail_closed():
    def bad(prompt):
        raise RuntimeError("gate down")

    r = m.run_script(m.SCRIPTS[0], bad)
    assert r["standalone_blocked"] is True
    assert r["trapped"] is True


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.MULTI_ATTACK_20_VERSION == "multi-attack-20.v1"
    assert m.SCHEMA_PIN == "northstar.multi-attack-20.v1"
