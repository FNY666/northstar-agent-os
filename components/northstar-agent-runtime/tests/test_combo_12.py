"""Tests for combo_12 (Resource-aware delegation)."""

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


combo = _load("combo_12")


def _d():
    d = combo.ResourceAwareDelegation("goal")
    d.register_command("ls", combo.cr.AutonomyLevel.AUTOMATIC)
    d.grant_preauth(5)
    return d


def test_delegate_ok():
    d = _d()
    r = d.delegate("ls", "ls", {}, {"n": 1}, ["t"])
    assert r["delegated"] is True
    assert r["done"] is False


def test_goal_done():
    d = _d()
    r = d.delegate("ls", "ls", {}, {}, [])
    assert r["done"] is True


def test_resource_bomb_fails():
    d = _d()
    try:
        d.delegate("ls", "e", {"x": "f(" * 60}, {}, [])
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_unknown_command_fails():
    d = _d()
    try:
        d.delegate("ghost", "ls", {}, {}, [])
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_stdlib_only():
    assert combo.stdlib_only() is True
