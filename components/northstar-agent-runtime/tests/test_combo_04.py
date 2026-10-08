"""Tests for combo_04 (Protected execution)."""

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


combo = _load("combo_04")


def _ex():
    dv = combo.dv
    return combo.ProtectedExecution(
        veto_consequences=[dv.Consequence.IRREVERSIBLE_BROAD]
    )


def test_clean_allowed():
    ex = _ex()
    r = ex.run("read", {"p": "/x"}, combo.dv.Consequence.REVERSIBLE_LOW)
    assert r["allowed"] is True


def test_resource_bomb_blocked():
    ex = _ex()
    try:
        ex.run("e", {"x": "f(" * 60}, combo.dv.Consequence.REVERSIBLE_LOW)
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_irreversible_vetoed():
    ex = _ex()
    try:
        ex.run("rm", {"p": "/"}, combo.dv.Consequence.IRREVERSIBLE_BROAD)
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_repeat_denies_rate_limit():
    ex = _ex()
    for _ in range(15):
        try:
            ex.run("e", {"x": "f(" * 60}, combo.dv.Consequence.REVERSIBLE_LOW)
        except combo.ComboError:
            pass
    limited, _ = ex._stateful.should_rate_limit(ex._session, "e")
    assert limited is True


def test_stdlib_only():
    assert combo.stdlib_only() is True
