"""Tests for monitor_04 (alert rules)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


al = _load("monitor_04")


def test_fires_and_resolves():
    mgr = al.AlertManager()
    mgr.add_rule(al.AlertRule(name="r", metric="m", op=">", threshold=1.0))
    assert len(mgr.evaluate({"m": 2.0})) == 1
    assert mgr.evaluate({"m": 0.5}) == []
    assert mgr.active() == []


def test_for_duration():
    mgr = al.AlertManager()
    mgr.add_rule(al.AlertRule(name="r", metric="m", op=">=", threshold=1.0, for_evals=3))
    assert mgr.evaluate({"m": 5.0}) == []
    assert mgr.evaluate({"m": 5.0}) == []
    assert len(mgr.evaluate({"m": 5.0})) == 1


def test_operators():
    mgr = al.AlertManager()
    mgr.add_rule(al.AlertRule(name="lt", metric="m", op="<", threshold=0.0))
    assert len(mgr.evaluate({"m": -1.0})) == 1


def test_bad_rule():
    import pytest

    with pytest.raises(al.AlertError):
        al.AlertRule(name="x", metric="m", op="~", threshold=1.0)


def test_bad_samples():
    import pytest

    mgr = al.AlertManager()
    with pytest.raises(al.AlertError):
        mgr.evaluate("nope")


def test_stdlib_only():
    assert al.stdlib_only() is True
