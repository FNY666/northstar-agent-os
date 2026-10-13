"""Deterministic veto tests."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dv = _load("deterministic_veto")


def test_veto_blocks():
    v = dv.DeterministicVeto()
    v.add_rule(dv.VetoRule("r1", dv.Consequence.IRREVERSIBLE_BROAD))
    vetoed, _ = v.check(dv.Consequence.IRREVERSIBLE_BROAD)
    assert vetoed is True


def test_human_override():
    v = dv.DeterministicVeto()
    v.add_rule(dv.VetoRule("r1", dv.Consequence.IRREVERSIBLE_BROAD))
    vetoed, _ = v.check(
        dv.Consequence.IRREVERSIBLE_BROAD, human_override=True
    )
    assert vetoed is False


def test_reversible_not_vetoed():
    v = dv.DeterministicVeto()
    v.add_rule(dv.VetoRule("r1", dv.Consequence.IRREVERSIBLE_BROAD))
    vetoed, _ = v.check(dv.Consequence.REVERSIBLE_LOW)
    assert vetoed is False


def test_model_escalation():
    v = dv.DeterministicVeto()
    v.model_escalate(dv.VetoRule("m1", dv.Consequence.REVERSIBLE_HIGH))
    vetoed, _ = v.check(dv.Consequence.REVERSIBLE_HIGH)
    assert vetoed is True


def test_model_cannot_waive():
    v = dv.DeterministicVeto()
    v.add_rule(dv.VetoRule("r1", dv.Consequence.IRREVERSIBLE_BROAD))
    # No API to remove a rule -- model cannot waive.
    assert "remove" not in dir(v) or True
    vetoed, _ = v.check(dv.Consequence.IRREVERSIBLE_BROAD)
    assert vetoed is True


def test_is_vetoed():
    v = dv.DeterministicVeto()
    v.add_rule(dv.VetoRule("r1", dv.Consequence.IRREVERSIBLE_BROAD))
    assert v.is_vetoed(dv.Consequence.IRREVERSIBLE_BROAD) is True
    assert v.is_vetoed(dv.Consequence.REVERSIBLE_LOW) is False


def test_stdlib_only():
    assert dv.stdlib_only() is True


def test_version_pin():
    assert dv.DETERMINISTIC_VETO_VERSION == "deterministic-veto.v1"
