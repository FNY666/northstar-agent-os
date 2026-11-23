"""Runtime defense 27 tests."""

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


rd = _load("runtime_defense_27")


def test_arm_and_trip():
    board = rd.KillSwitchBoard()
    board.arm("k1", "task")
    assert board.is_dead("task") is False
    board.trip("k1", "test")
    assert board.is_dead("task") is True


def test_global_covers_all():
    board = rd.KillSwitchBoard()
    board.arm("g", "global")
    board.trip("g", "incident")
    assert board.is_dead("task") is True
    assert board.is_dead("session") is True


def test_scope_isolation():
    board = rd.KillSwitchBoard()
    board.arm("k1", "task")
    board.trip("k1", "test")
    assert board.is_dead("session") is False


def test_unknown_switch():
    board = rd.KillSwitchBoard()
    with pytest.raises(rd.KillSwitchError):
        board.trip("ghost", "x")


def test_double_arm():
    board = rd.KillSwitchBoard()
    board.arm("k1", "task")
    with pytest.raises(rd.KillSwitchError):
        board.arm("k1", "task")


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_27_VERSION == "runtime-defense-27.v1"
