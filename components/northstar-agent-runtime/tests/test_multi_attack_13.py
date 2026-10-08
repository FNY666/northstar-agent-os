"""Tests for multi_attack_13 (low-ball)."""
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


m = _load("multi_attack_13")


def test_term_change_stops_without_reauth():
    result = m.run_script(m.SCRIPTS[0], lambda changes: False)
    assert result["stopped"] is True
    assert result["stopped_turn"] == 2
    key, old, new = result["term_changes"][0]["changes"][0]
    assert key == "scope" and old == "temp" and new == "temp+cache"


def test_reauth_allows():
    result = m.run_script(m.SCRIPTS[1], lambda changes: True)
    assert result["stopped"] is False


def test_no_changes_clean():
    clean = m.LowBallScript("c", "x", [
        m.LowBallTurn(1, "do x", {"a": "1"}, commits=True),
        m.LowBallTurn(2, "do x again", {"a": "1"}),
    ])
    result = m.run_script(clean, lambda changes: False)
    assert result["stopped"] is False
    assert result["term_changes"] == []


def test_reauth_exception_fail_closed():
    def bad(changes):
        raise RuntimeError("reauth down")

    result = m.run_script(m.SCRIPTS[0], bad)
    assert result["stopped"] is True


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.MULTI_ATTACK_13_VERSION == "multi-attack-13.v1"
    assert m.SCHEMA_PIN == "northstar.multi-attack-13.v1"
