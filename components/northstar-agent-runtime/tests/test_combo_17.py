"""Tests for combo_17 (Confidence-calibrated output)."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


combo = _load("combo_17")


def _prod():
    schema = combo.so.VerdictSchema(
        "s", [combo.so.FieldSpec("answer", "str", True)]
    )
    return combo.ConfidenceCalibratedOutput(schema)


def test_produces():
    p = _prod()
    r = p.produce({"answer": "yes"}, 95, "low")
    assert r["output"]["answer"] == "yes"


def test_pii_scrubbed():
    p = _prod()
    r = p.produce({"answer": "mail amy@example.com"}, 95, "low")
    assert "amy@example.com" not in r["output"]["answer"]


def test_low_confidence_denied():
    p = _prod()
    try:
        p.produce({"answer": "yes"}, 5, "high")
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_bad_schema_fails():
    p = _prod()
    try:
        p.produce({"nope": 1}, 95, "low")
    except Exception:
        return
    raise AssertionError("expected schema error")


def test_stdlib_only():
    assert combo.stdlib_only() is True
