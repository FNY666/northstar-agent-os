"""Deliberative spec tests."""

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


ds = _load("deliberative_spec")


def test_valid():
    spec = {"S1": ds.SpecClause("S1", "text")}
    d = ds.require_citation("allow", ["S1"], "reason", spec)
    assert d.decision == "allow"


def test_no_citation():
    spec = {"S1": ds.SpecClause("S1", "text")}
    with pytest.raises(ds.DeliberativeError):
        ds.require_citation("allow", [], "reason", spec)


def test_unknown_clause():
    spec = {"S1": ds.SpecClause("S1", "text")}
    with pytest.raises(ds.DeliberativeError):
        ds.require_citation("allow", ["S999"], "reason", spec)


def test_bad_decision():
    spec = {"S1": ds.SpecClause("S1", "text")}
    with pytest.raises(ds.DeliberativeError):
        ds.require_citation("maybe", ["S1"], "reason", spec)


def test_empty_reasoning():
    spec = {"S1": ds.SpecClause("S1", "text")}
    with pytest.raises(ds.DeliberativeError):
        ds.require_citation("allow", ["S1"], "", spec)


def test_stdlib_only():
    assert ds.stdlib_only() is True


def test_version_pin():
    assert ds.DELIBERATIVE_VERSION == "deliberative-spec.v1"
