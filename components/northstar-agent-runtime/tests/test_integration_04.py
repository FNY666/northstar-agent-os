"""Integration 04 tests."""

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


pv = _load("pii_vault")
so = _load("structured_output")
i04 = _load("integration_04")


def test_emit_masks_pii():
    out = i04.VaultAwareOutput(pv.Vault(), "run1")
    v = out.emit(
        {
            "verdict": "allow",
            "reason": "sent to john@example.com",
            "tool": "send",
        },
        so.GATE_VERDICT_SCHEMA,
    )
    assert "john@example.com" not in v["reason"]
    assert "[EMAIL_0]" in v["reason"]
    assert v["verdict"] == "allow"


def test_emit_rejects_bad_schema():
    out = i04.VaultAwareOutput(pv.Vault(), "run1")
    with pytest.raises(i04.StructuredOutputError):
        out.emit(
            {"verdict": "allow", "reason": "x"},
            so.GATE_VERDICT_SCHEMA,
        )


def test_demask_restores():
    out = i04.VaultAwareOutput(pv.Vault(), "run1")
    v = out.emit(
        {
            "verdict": "allow",
            "reason": "to john@example.com",
            "tool": "send",
        },
        so.GATE_VERDICT_SCHEMA,
    )
    assert "john@example.com" in out.demask(v["reason"])


def test_non_string_fields_untouched():
    out = i04.VaultAwareOutput(pv.Vault(), "run1")
    v = out.emit(
        {"verdict": "deny", "reason": "ok", "tool": "x"},
        so.GATE_VERDICT_SCHEMA,
    )
    assert v["verdict"] == "deny"


def test_version_pin():
    assert i04.INTEGRATION_04_VERSION == "integration-04.v1"
    assert i04.stdlib_only() is True
