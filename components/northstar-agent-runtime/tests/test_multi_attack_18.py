"""Tests for multi_attack_18 (false premise injection)."""
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


m = _load("multi_attack_18")

FACTS = {
    "the backup is complete": False,
    "the agent has admin approval": False,
    "the approval covers destructive operations": None,
    "the tool returned 3 files": True,
}


def _checker(premise):
    return FACTS.get(premise)


def test_false_premise_caught():
    r = m.run_script(m.SCRIPTS[0], _checker, lambda p: False)
    assert r["premise_turn"] == 1
    assert r["stopped"] is True


def test_unknown_premise_fail_closed():
    r = m.run_script(m.SCRIPTS[1], _checker, lambda p: False)
    # turn 1: refuted premise; turn 2 would be unknown -- stopped at 1
    assert r["premise_turn"] == 1
    assert r["stopped"] is True


def test_true_premise_passes():
    r = m.run_script(m.SCRIPTS[2], _checker, lambda p: False)
    assert r["stopped"] is False


def test_checker_exception_fail_closed():
    def bad(premise):
        raise RuntimeError("checker down")

    turn = m.PremiseTurn(1, "p", premises=["anything"])
    assert m.check_premises(turn, bad) == ["anything"]


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.MULTI_ATTACK_18_VERSION == "multi-attack-18.v1"
    assert m.SCHEMA_PIN == "northstar.multi-attack-18.v1"
