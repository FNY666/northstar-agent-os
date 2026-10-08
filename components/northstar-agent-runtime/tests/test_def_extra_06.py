"""Tests for def_extra_06 (adaptive authentication mock)."""
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


m = _load("def_extra_06")


def test_level_mapping():
    assert m.required_level(0.0) == "none"
    assert m.required_level(10.0) == "password"
    assert m.required_level(30.0) == "otp"
    assert m.required_level(60.0) == "step-up"
    assert m.required_level(90.0) == "deny"


def test_sufficient_factors_ok():
    ok, req = m.evaluate(30.0, ["password", "otp"])
    assert ok is True
    assert req == "otp"


def test_insufficient_factors_denied():
    ok, req = m.evaluate(30.0, ["password"])
    assert ok is False
    assert req == "otp"


def test_deny_never_satisfied():
    ok, req = m.evaluate(90.0, ["password", "otp", "step-up"])
    assert ok is False
    assert req == "deny"


def test_bad_score_fail_closed():
    with pytest.raises(m.AdaptiveAuthError):
        m.required_level(150.0)


def test_version_pin():
    assert m.DEF_EXTRA_06_VERSION == "def-extra-06.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-06.v1"
