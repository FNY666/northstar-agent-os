"""Tests for monitor_12 (YARA mock)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


yr = _load("monitor_12")


def test_any_of_them():
    eng = yr.YaraEngine()
    eng.add_rule('rule A { strings: $a = "bad" $b = /evil[0-9]+/ condition: any of them }')
    assert eng.scan("totally bad") == ["A"]
    assert eng.scan("evil42 here") == ["A"]
    assert eng.scan("clean") == []


def test_all_of_them():
    eng = yr.YaraEngine()
    eng.add_rule('rule B { strings: $a = "foo" $b = "bar" condition: all of them }')
    assert eng.scan("foo bar") == ["B"]
    assert eng.scan("foo") == []


def test_boolean_condition():
    eng = yr.YaraEngine()
    eng.add_rule('rule C { strings: $a = "x" $b = "y" condition: $a and not $b }')
    assert eng.scan("has x") == ["C"]
    assert eng.scan("x and y") == []


def test_bad_grammar():
    import pytest

    with pytest.raises(yr.YaraError):
        yr.parse_rule("not a rule")
    with pytest.raises(yr.YaraError):
        yr.parse_rule('rule N { strings: $a = "x" }')


def test_stdlib_only():
    assert yr.stdlib_only() is True
