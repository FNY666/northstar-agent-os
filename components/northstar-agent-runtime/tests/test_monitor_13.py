"""Tests for monitor_13 (Sigma mock)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


sg = _load("monitor_13")


def test_selection_and_filter():
    r = sg.SigmaRule(
        title="t",
        selections={
            "selection": sg.Selection("selection", {"A": "1"}),
            "filter": sg.Selection("filter", {"B": "2"}),
        },
        condition="selection and filter",
    )
    assert r.matches({"A": "1", "B": "2"}) is True
    assert r.matches({"A": "1", "B": "3"}) is False


def test_modifiers_and_lists():
    s = sg.Selection("s", {"Msg|contains": ["denied", "blocked"]})
    assert s.matches({"Msg": "access denied"}) is True
    assert s.matches({"Msg": "ok"}) is False


def test_one_of():
    r = sg.SigmaRule(
        title="t",
        selections={
            "sel_a": sg.Selection("sel_a", {"X": "1"}),
            "sel_b": sg.Selection("sel_b", {"X": "2"}),
        },
        condition="1 of sel_*",
    )
    assert r.matches({"X": "2"}) is True
    assert r.matches({"X": "9"}) is False


def test_bad_selection():
    import pytest

    with pytest.raises(sg.SigmaError):
        sg.SigmaRule(title="t", selections={}, condition="selection")
    with pytest.raises(sg.SigmaError):
        sg.Selection("s", {"F|bogus": "v"}).matches({"F": "v"})


def test_stdlib_only():
    assert sg.stdlib_only() is True
