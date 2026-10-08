"""Tests for dx_16. code actions."""
import importlib.util, sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent

def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m

dx = _load("dx_16")

def _cat():
    c = dx.ActionCatalog()
    c.register(dx.CodeAction("q1", "quickfix", "Add import", "a.py", 1, 3))
    c.register(dx.CodeAction("r1", "refactor", "Extract fn", "a.py", 2, 5))
    return c


def test_actions_for_range():
    acts = _cat().actions_for("a.py", 2)
    assert [a.action_id for a in acts] == ["q1", "r1"]


def test_outside_range_empty():
    assert _cat().actions_for("a.py", 9) == []


def test_unknown_kind_raises():
    c = dx.ActionCatalog()
    with pytest.raises(dx.CodeActionsError):
        c.register(dx.CodeAction("x", "bogus", "T", "a.py", 1, 1))


def test_duplicate_raises():
    with pytest.raises(dx.CodeActionsError):
        _cat().register(dx.CodeAction("q1", "quickfix", "dup", "a.py", 1, 1))


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX16_ACTIONS_VERSION == "dx-code-actions.v1"
