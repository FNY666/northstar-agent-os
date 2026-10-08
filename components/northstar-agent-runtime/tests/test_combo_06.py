"""Tests for combo_06 (Gated delegation)."""

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


combo = _load("combo_06")


def _gd(score=0.1):
    fs = combo.fs
    floors = [fs.Floor("f1", min_severity=10, required_detectors=frozenset({"tw"}))]
    gd = combo.GatedDelegation(lambda tool, args: score, floors)
    gd.register_command("ls", combo.cr.AutonomyLevel.AUTOMATIC)
    return gd


def test_authorized():
    gd = _gd()
    r = gd.authorize("ls", "ls", {}, frozenset({"tw"}), frozenset(), 50)
    assert r["authorized"] is True


def test_tier_deny():
    gd = _gd(score=0.95)
    try:
        gd.authorize("ls", "ls", {}, frozenset({"tw"}), frozenset(), 50)
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_unknown_command():
    gd = _gd()
    try:
        gd.authorize("ghost", "ls", {}, frozenset({"tw"}), frozenset(), 50)
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_floor_violation():
    gd = _gd()
    try:
        gd.authorize("ls", "ls", {}, frozenset(), frozenset(), 50)
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_stdlib_only():
    assert combo.stdlib_only() is True
