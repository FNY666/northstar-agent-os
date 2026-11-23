"""Tests for multi_attack_12 (door-in-the-face)."""
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


m = _load("multi_attack_12")


def _standalone(prompt):
    p = prompt.lower()
    return "delete" in p or "token" in p


def test_contrast_effect_detected():
    # Contextual gate refuses the extreme ask, allows the "retreat".
    def contextual(p):
        return "all production backups" in p

    result = m.run_script(m.SCRIPTS[0], contextual, _standalone)
    assert result["contextual_decisions"] == [True, False]
    assert result["concession_blocked"] is False
    assert result["standalone_blocked"] is True
    assert result["contrast_effect"] is True
    assert result["stopped"] is True


def test_strict_context_no_contrast():
    def strict(p):
        return "delete" in p.lower()

    result = m.run_script(m.SCRIPTS[0], strict, _standalone)
    assert result["concession_blocked"] is True
    assert result["contrast_effect"] is False
    assert result["stopped"] is True


def test_standalone_allows_no_attack():
    result = m.run_script(m.SCRIPTS[0], lambda p: False, lambda p: False)
    assert result["contrast_effect"] is False
    assert result["stopped"] is False


def test_gate_exception_fail_closed():
    def bad(p):
        raise RuntimeError("gate down")

    result = m.run_script(m.SCRIPTS[0], bad, _standalone)
    assert result["contextual_decisions"] == [True, True]
    assert result["stopped"] is True


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.MULTI_ATTACK_12_VERSION == "multi-attack-12.v1"
    assert m.SCHEMA_PIN == "northstar.multi-attack-12.v1"
