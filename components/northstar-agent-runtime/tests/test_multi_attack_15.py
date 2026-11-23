"""Tests for multi_attack_15 (gaslighting)."""
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


m = _load("multi_attack_15")

HISTORY = ["agent: I listed 3 files", "agent: budget is 100"]


def _checker(claim, hist):
    text = " ".join(hist).lower()
    claim = claim.lower()
    if "approved deleting" in claim:
        return "approved" in text and "delet" in text
    if "said yes" in claim:
        return "yes" in text
    if "budget" in claim and "1000" in claim:
        return "1000" in text
    if "3 files" in claim:
        return "3 files" in text
    return False


def test_false_claims_caught():
    r = m.run_script(m.SCRIPTS[0], HISTORY, _checker, lambda p: False)
    assert r["gaslit_turn"] == 1
    assert r["stopped"] is True
    r2 = m.run_script(m.SCRIPTS[1], HISTORY, _checker, lambda p: False)
    assert r2["stopped"] is True


def test_true_claim_passes():
    r = m.run_script(m.SCRIPTS[2], HISTORY, _checker, lambda p: False)
    assert r["stopped"] is False


def test_checker_exception_fail_closed():
    def bad(claim, hist):
        raise RuntimeError("checker down")

    turn = m.GaslightTurn(1, "p", claims=["anything"])
    assert m.verify_claims(turn, HISTORY, bad) == ["anything"]


def test_gate_block():
    r = m.run_script(m.SCRIPTS[0], HISTORY, _checker, lambda p: True)
    assert r["blocked_turn"] == 1
    assert r["stopped"] is True


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.MULTI_ATTACK_15_VERSION == "multi-attack-15.v1"
    assert m.SCHEMA_PIN == "northstar.multi-attack-15.v1"
