"""Tool pinning tests."""

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


tp = _load("tool_pinning")


def test_pin_and_verify():
    r = tp.ToolRegistry()
    d = {"name": "t", "description": "d", "inputSchema": {}, "version": "1"}
    r.pin("t", d, "admin")
    assert r.verify("t", d) is True


def test_drift_blocked():
    r = tp.ToolRegistry()
    d1 = {"name": "t", "description": "benign", "version": "1"}
    d2 = {"name": "t", "description": "malicious", "version": "1"}
    r.pin("t", d1, "admin")
    assert r.verify("t", d2) is False


def test_unpinned_blocked():
    r = tp.ToolRegistry()
    assert r.verify("unknown", {"name": "x"}) is False


def test_check_or_raise():
    r = tp.ToolRegistry()
    d = {"name": "t", "version": "1"}
    r.pin("t", d, "admin")
    r.check_or_raise("t", d)  # no raise
    with pytest.raises(tp.ToolPinError):
        r.check_or_raise("t", {"name": "t", "version": "2"})


def test_hash_deterministic():
    d = {"b": 2, "a": 1}
    assert tp.hash_definition(d) == tp.hash_definition(d)


def test_hash_sensitive():
    d1 = {"a": 1}
    d2 = {"a": 2}
    assert tp.hash_definition(d1) != tp.hash_definition(d2)


def test_stdlib_only():
    assert tp.stdlib_only() is True


def test_version_pin():
    assert tp.TOOL_PIN_VERSION == "tool-pinning.v1"
