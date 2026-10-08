"""Tests for combo_19 (Multi-turn immune)."""

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


combo = _load("combo_19")


def test_trajectory_stops():
    im = combo.MultiTurnImmune()
    script = combo.cp.SCRIPTS[0]
    r = im.run_turns(script, lambda p: False, lambda ps: 0.95, [90] * 5)
    assert r["stopped"] is True
    assert r["stop_reason"] == "trajectory"


def test_turn_block_records_risk():
    im = combo.MultiTurnImmune()
    script = combo.cp.SCRIPTS[0]
    r = im.run_turns(script, lambda p: "verbatim" in p, lambda ps: 0.0, [90] * 5)
    assert r["stopped"] is True
    assert r["risk"] > 0


def test_benign_passes():
    im = combo.MultiTurnImmune()
    script = combo.cp.SCRIPTS[0]
    r = im.run_turns(script, lambda p: False, lambda ps: 0.1, [95] * 5)
    assert r["stopped"] is False


def test_stdlib_only():
    assert combo.stdlib_only() is True
