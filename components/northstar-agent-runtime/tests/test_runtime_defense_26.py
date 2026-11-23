"""Runtime defense 26 tests."""

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


rd = _load("runtime_defense_26")


def _profile():
    return rd.BehaviorProfile(
        transitions={"a": frozenset({"b"}), "b": frozenset({"a"})},
        entry_tools=frozenset({"a"}),
    )


def test_legal_sequence():
    an = rd.BehaviorAnalyzer(_profile())
    assert an.observe("a")[0] is True
    assert an.observe("b")[0] is True
    assert an.observe("a")[0] is True


def test_illegal_transition():
    an = rd.BehaviorAnalyzer(_profile())
    an.observe("a")
    ok, reason = an.observe("a")  # a -> a not allowed
    assert ok is False
    assert "illegal transition" in reason


def test_bad_entry():
    an = rd.BehaviorAnalyzer(_profile())
    ok, _ = an.observe("b")
    assert ok is False


def test_reset():
    an = rd.BehaviorAnalyzer(_profile())
    an.observe("a")
    an.reset()
    assert an.history == []


def test_rejects_empty_profile():
    with pytest.raises(rd.BehaviorError):
        rd.BehaviorProfile(transitions={})


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_26_VERSION == "runtime-defense-26.v1"
