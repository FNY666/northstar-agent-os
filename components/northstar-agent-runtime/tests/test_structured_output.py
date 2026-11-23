"""Structured output tests."""

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


so = _load("structured_output")


def test_valid():
    v = so.validate(
        {"verdict": "allow", "reason": "ok", "tool": "t"},
        so.GATE_VERDICT_SCHEMA,
    )
    assert v["verdict"] == "allow"


def test_missing_required():
    with pytest.raises(so.StructuredOutputError):
        so.validate({"verdict": "allow"}, so.GATE_VERDICT_SCHEMA)


def test_wrong_type():
    with pytest.raises(so.StructuredOutputError):
        so.validate(
            {"verdict": "allow", "reason": 123, "tool": "t"},
            so.GATE_VERDICT_SCHEMA,
        )


def test_disallowed_value():
    with pytest.raises(so.StructuredOutputError):
        so.validate(
            {"verdict": "maybe", "reason": "x", "tool": "t"},
            so.GATE_VERDICT_SCHEMA,
        )


def test_strips_unknown():
    v = so.validate(
        {"verdict": "deny", "reason": "x", "tool": "t", "injected": "bad"},
        so.GATE_VERDICT_SCHEMA,
    )
    assert "injected" not in v


def test_bool_not_int():
    schema = so.VerdictSchema(
        "test", [so.FieldSpec("count", "int", True)]
    )
    with pytest.raises(so.StructuredOutputError):
        so.validate({"count": True}, schema)


def test_stdlib_only():
    assert so.stdlib_only() is True


def test_version_pin():
    assert so.STRUCTURED_OUTPUT_VERSION == "structured-output.v1"
